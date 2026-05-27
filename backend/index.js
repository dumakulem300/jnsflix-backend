// File location: backend/index.js
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();

// Environment variables validation
const requiredEnvVars = [
  'PAYMONGO_SECRET_KEY',
  'PAYMONGO_WEBHOOK_SECRET',
  'FIREBASE_PROJECT_ID',
  'FIREBASE_SERVICE_ACCOUNT_JSON',
  'BASE_URL'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const PAYMONGO_SECRET_KEY = process.env.PAYMONGO_SECRET_KEY;
const PAYMONGO_WEBHOOK_SECRET = process.env.PAYMONGO_WEBHOOK_SECRET;
const BASE_URL = process.env.BASE_URL || 'http://localhost:5173';
const PORT = process.env.PORT || 3000;

// Allowed origins for CORS
const allowedOrigins = [
  BASE_URL,
  'http://localhost:5173',
  'http://localhost:3000',
  'https://jnsflix.onrender.com'
];

// Initialize Firebase Admin SDK
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: process.env.FIREBASE_PROJECT_ID,
});
const db = admin.firestore();

// Global middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
app.use(express.json()); // Parse JSON for all routes except webhook

// Helper: Verify Firebase ID token
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

// Helper: Create PayMongo checkout session
async function createPayMongoCheckout(amount, description, referenceId) {
  const auth = Buffer.from(`${PAYMONGO_SECRET_KEY}:`).toString('base64');
  const response = await axios.post(
    'https://api.paymongo.com/v1/checkout_sessions',
    {
      data: {
        attributes: {
          amount: amount * 100,
          description: description,
          currency: 'PHP',
          success_url: `${BASE_URL}/payment-success?session_id={checkout_session_id}`,
          cancel_url: `${BASE_URL}/payment-cancel`,
          reference_number: referenceId,
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

// Endpoint: POST /api/create-payment (authenticated)
app.post('/api/create-payment', verifyFirebaseToken, async (req, res) => {
  try {
    const { amount, description, movieId } = req.body;
    const userId = req.user.uid;

    if (!amount || !description || !movieId) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify user exists in Firestore (optional)
    const userSnapshot = await db.collection('users').doc(userId).get();
    if (!userSnapshot.exists) {
      // Create user document if not exists
      await db.collection('users').doc(userId).set({
        email: req.user.email,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    const referenceId = `movie_${movieId}_user_${userId}_${Date.now()}`;
    const paymongoData = await createPayMongoCheckout(amount, description, referenceId);
    const checkoutUrl = paymongoData.data.attributes.checkout_url;
    const sessionId = paymongoData.data.id;

    await db.collection('payments').doc(sessionId).set({
      userId,
      movieId,
      amount,
      description,
      referenceId,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      checkoutUrl,
    });

    res.json({ checkoutUrl, sessionId });
  } catch (error) {
    console.error('Create payment error:', error);
    res.status(500).json({ error: 'Failed to create payment session' });
  }
});

// Endpoint: GET /api/payment-status (authenticated)
app.get('/api/payment-status', verifyFirebaseToken, async (req, res) => {
  try {
    const { sessionId } = req.query;
    if (!sessionId) {
      return res.status(400).json({ error: 'sessionId required' });
    }

    const paymentDoc = await db.collection('payments').doc(sessionId).get();
    if (!paymentDoc.exists) {
      return res.status(404).json({ error: 'Payment not found' });
    }

    const payment = paymentDoc.data();
    // Ensure user owns this payment
    if (payment.userId !== req.user.uid) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    res.json({ status: payment.status });
  } catch (error) {
    console.error('Payment status error:', error);
    res.status(500).json({ error: 'Failed to get payment status' });
  }
});

// Webhook route: POST /api/paymongo-webhook (uses raw body for signature verification)
app.post('/api/paymongo-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['paymongo-signature'];
  if (!signature) {
    return res.status(401).send('Missing signature');
  }

  const rawBody = req.body; // Buffer
  const hash = crypto
    .createHmac('sha256', PAYMONGO_WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  if (hash !== signature) {
    return res.status(401).send('Invalid signature');
  }

  const event = JSON.parse(rawBody.toString());
  const eventData = event.data;

  // Correct event type: checkout_session.payment_paid
  if (event.type === 'checkout_session.payment_paid') {
    const sessionId = eventData.id;
    const paymentRef = db.collection('payments').doc(sessionId);
    const paymentDoc = await paymentRef.get();

    if (paymentDoc.exists) {
      const payment = paymentDoc.data();
      await paymentRef.update({
        status: 'paid',
        paidAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      await db.collection('users').doc(payment.userId).collection('purchases').add({
        movieId: payment.movieId,
        amount: payment.amount,
        purchasedAt: admin.firestore.FieldValue.serverTimestamp(),
        sessionId,
      });
    }
  }

  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});