// File location: backend/index.js
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();

// Environment variables validation with detailed logging
console.log('Starting server, checking environment variables...');
const requiredEnvVars = [
  'PAYMONGO_SECRET_KEY',
  'PAYMONGO_WEBHOOK_SECRET',
  'FIREBASE_PROJECT_ID',
  'FIREBASE_SERVICE_ACCOUNT_JSON',
  'BASE_URL',
  'ADMIN_EMAIL'
];

let missingVars = [];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    missingVars.push(envVar);
  }
}
if (missingVars.length > 0) {
  console.error('Exiting due to missing environment variables');
  process.exit(1);
}

const PAYMONGO_SECRET_KEY = process.env.PAYMONGO_SECRET_KEY;
const PAYMONGO_WEBHOOK_SECRET = process.env.PAYMONGO_WEBHOOK_SECRET;
const PAYMONGO_PLAN_ID = process.env.PAYMONGO_PLAN_ID; // optional
let BASE_URL = process.env.BASE_URL || 'http://localhost:5173';

if (BASE_URL.endsWith('/')) {
  BASE_URL = BASE_URL.slice(0, -1);
  console.log(`Normalized BASE_URL: ${BASE_URL}`);
}
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const PORT = process.env.PORT || 3000;

const allowedOrigins = [
  BASE_URL,
  'http://localhost:5173',
  'http://localhost:3000',
  'https://jnsflix.onrender.com'
];

// Parse Firebase service account JSON (simple trim)
let serviceAccount;
try {
  const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON.trim();
  serviceAccount = JSON.parse(rawJson);
} catch (err) {
  console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON:', err.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: process.env.FIREBASE_PROJECT_ID,
});
const db = admin.firestore();
console.log('Firebase Admin initialized');

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));

/**
 * Webhook Raw Body Middleware Placement
 * We use express.json() globally BUT exclude the webhook route,
 * allowing the webhook route to handle its own express.raw() parsing natively.
 */
app.use((req, res, next) => {
  if (req.originalUrl === '/api/paymongo-webhook') {
    next();
  } else {
    express.json()(req, res, next);
  }
});

// Root route to confirm server is running
app.get('/', (req, res) => {
  res.status(200).send('JNSflix Backend is running!');
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
}

async function verifyAdmin(req, res, next) {
  if (!req.user || req.user.email !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Forbidden: Admin access required' });
  }
  next();
}

async function createPayMongoSubscription(userId) {
  const auth = Buffer.from(`${PAYMONGO_SECRET_KEY}:`).toString('base64');
  const response = await axios.post(
    'https://api.paymongo.com/v1/checkout_sessions',
    {
      data: {
        attributes: {
          type: 'subscription',
          plan_id: PAYMONGO_PLAN_ID,
          success_url: `${BASE_URL}/subscription-success?session_id={checkout_session_id}`,
          cancel_url: `${BASE_URL}/subscription-cancel`,
          reference_number: `sub_${userId}_${Date.now()}`,
          payment_method_types: ['card', 'gcash'],
          send_email_receipt: true
        },
      },
    },
    {
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
    }
  );
  return response.data;
}

app.post('/api/create-subscription', verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.user.uid;

    const userDoc = await db.collection('users').doc(userId).get();
    const subscription = userDoc.data()?.subscription;
    if (subscription && subscription.active === true && subscription.endDate?.toDate() > new Date()) {
      return res.status(400).json({ error: 'User already has an active subscription' });
    }

    const paymongoData = await createPayMongoSubscription(userId);
    const checkoutUrl = paymongoData.data.attributes.checkout_url;
    const sessionId = paymongoData.data.id;

    await db.collection('subscription_checkouts').doc(sessionId).set({
      userId,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      checkoutUrl,
    });

    res.json({ checkoutUrl, sessionId });
  } catch (error) {
    console.error('Create subscription error:', error);
    res.status(500).json({ error: 'Failed to create subscription session' });
  }
});

app.get('/api/subscription-status', verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const userDoc = await db.collection('users').doc(userId).get();

    if (!userDoc.exists) {
      return res.json({ active: false });
    }

    const subscription = userDoc.data().subscription;
    if (!subscription || !subscription.active) {
      return res.json({ active: false });
    }

    const now = new Date();
    const endDate = subscription.endDate.toDate();
    if (endDate < now) {
      await db.collection('users').doc(userId).update({
        'subscription.active': false
      });
      return res.json({ active: false });
    }

    return res.json({
      active: true,
      expiresAt: endDate.toISOString()
    });
  } catch (error) {
    console.error('Subscription status error:', error);
    res.status(500).json({ error: 'Failed to get subscription status' });
  }
});

/**
 * Correct Webhook Signature Verification for PayMongo
 */
app.post('/api/paymongo-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const signatureHeader = req.headers['paymongo-signature'];
  if (!signatureHeader) {
    return res.status(401).send('Missing signature header');
  }

  const rawBody = req.body.toString();

  try {
    // PayMongo signatures come formatted as: t=timestamp,te=signature,v1=signature
    const pairs = signatureHeader.split(',');
    let timestamp = '';
    let v1Signature = '';

    for (const pair of pairs) {
      const [key, value] = pair.split('=');
      if (key === 't') timestamp = value;
      if (key === 'v1') v1Signature = value;
    }

    if (!timestamp || !v1Signature) {
      return res.status(401).send('Invalid signature format');
    }

    // PayMongo signs a string made of: timestamp + "." + rawBody
    const toVerify = `${timestamp}.${rawBody}`;
    const calculatedHash = crypto
      .createHmac('sha256', PAYMONGO_WEBHOOK_SECRET)
      .update(toVerify)
      .digest('hex');

    if (calculatedHash !== v1Signature) {
      console.error('Signature mismatch!');
      return res.status(401).send('Invalid signature verification');
    }

    // Safely parse JSON payload now that authenticity is verified
    const event = JSON.parse(rawBody);
    const eventData = event.data;

    if (event.type === 'subscription.activated') {
      const sessionId = eventData.attributes.checkout_session_id;
      const subscriptionId = eventData.id;  // FIXED: was event.data.id, now correct

      const checkoutDoc = await db.collection('subscription_checkouts').doc(sessionId).get();
      if (checkoutDoc.exists) {
        const { userId } = checkoutDoc.data();
        const startDate = new Date();
        const endDate = new Date();
        endDate.setDate(endDate.getDate() + 30);

        await db.collection('users').doc(userId).set({
          subscription: {
            active: true,
            subscriptionId: subscriptionId,
            startDate: admin.firestore.Timestamp.fromDate(startDate),
            endDate: admin.firestore.Timestamp.fromDate(endDate)
          }
        }, { merge: true });

        await db.collection('subscription_checkouts').doc(sessionId).update({
          status: 'activated',
          subscriptionId: subscriptionId
        });
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook payload error:', err.message);
    res.status(400).send('Webhook processing failed');
  }
});

app.post('/api/admin/create-plan', verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const { name, amount, interval, intervalCount = 1 } = req.body;
    if (!name || !amount || !interval) {
      return res.status(400).json({ error: 'Missing required fields: name, amount, interval' });
    }

    const amountInCentavos = Math.round(amount * 100);
    const auth = Buffer.from(`${PAYMONGO_SECRET_KEY}:`).toString('base64');

    const response = await axios.post(
      'https://api.paymongo.com/v1/subscriptions/plans',
      {
        data: {
          attributes: {
            name,
            amount: amountInCentavos,
            currency: 'PHP',
            interval,
            interval_count: intervalCount,
          }
        }
      },
      {
        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type': 'application/json',
        },
      }
    );

    const plan = response.data.data;
    res.json({
      plan_id: plan.id,
      name: plan.attributes.name,
      amount: plan.attributes.amount / 100,
      currency: plan.attributes.currency,
      interval: plan.attributes.interval,
      interval_count: plan.attributes.interval_count,
    });
  } catch (error) {
    console.error('Create plan error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to create plan' });
  }
});

app.get('/api/admin/plans', verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const auth = Buffer.from(`${PAYMONGO_SECRET_KEY}:`).toString('base64');
    const response = await axios.get(
      'https://api.paymongo.com/v1/subscriptions/plans',
      {
        headers: {
          Authorization: `Basic ${auth}`,
        },
      }
    );

    const plans = response.data.data.map(plan => ({
      id: plan.id,
      name: plan.attributes.name,
      amount: plan.attributes.amount / 100,
      currency: plan.attributes.currency,
      interval: plan.attributes.interval,
      interval_count: plan.attributes.interval_count,
      created_at: plan.attributes.created_at,
    }));

    res.json({ plans });
  } catch (error) {
    console.error('Fetch plans error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to fetch plans', 
      details: error.response?.data || error.message 
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: ${BASE_URL}/health`);
});