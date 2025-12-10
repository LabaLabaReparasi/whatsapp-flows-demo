require('dotenv').config();
const express = require('express');
const crypto = require('crypto');

const app = express();
// We need raw body to validate signature. Use bodyParser with verify to keep raw buffer.
const bodyParser = require('body-parser');
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    // attach raw body for signature verification
    req.rawBody = buf;
  }
}));

const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_verify_token';
const APP_SECRET = process.env.APP_SECRET || 'replace_with_your_app_secret';

// GET endpoint for webhook verification (Meta challenge)
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('Webhook verified');
      res.status(200).send(challenge);
    } else {
      res.sendStatus(403);
    }
  } else {
    res.sendStatus(400);
  }
});

// POST endpoint to receive Flow submissions / events
app.post('/webhook', (req, res) => {
  // Signature sent by Meta in header: "x-hub-signature-256"
  const signatureHeader = req.get('x-hub-signature-256') || '';
  const raw = req.rawBody || Buffer.from(JSON.stringify(req.body));

  // compute HMAC SHA256
  const expectedSig = 'sha256=' + crypto.createHmac('sha256', APP_SECRET).update(raw).digest('hex');

  if (!signatureHeader || !crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(signatureHeader))) {
    console.warn('Invalid signature', signatureHeader, expectedSig);
    return res.sendStatus(401);
  }

  // At this point signature validated. Process the body:
  const body = req.body;
  console.log('Received payload:', JSON.stringify(body).slice(0, 1000));

  // Example: handle a flow submission event
  // (actual paths/fields follow Meta's Flow webhook format)
  // TODO: add your business logic here (save to DB, call other APIs, respond to user, etc.)

  // Always respond 200 quickly
  res.sendStatus(200);
});

// optional health-check
app.get('/', (req, res) => res.send('OK - 👍🏽'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on ${port}`));
