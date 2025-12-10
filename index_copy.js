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
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL || '';

function forwardToMake(payload) {
  if (!MAKE_WEBHOOK_URL) return Promise.resolve({ skipped: true });
  const url = new URL(MAKE_WEBHOOK_URL);
  const data = JSON.stringify(payload);
  const isHttps = url.protocol === 'https:';
  const mod = isHttps ? require('https') : require('http');
  const options = {
    method: 'POST',
    hostname: url.hostname,
    port: url.port || (isHttps ? 443 : 80),
    path: url.pathname + url.search,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data)
    }
  };
  return new Promise((resolve, reject) => {
    const req = mod.request(options, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

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

  forwardToMake(body).then((r) => {
    if (r && r.skipped) {
      console.warn('MAKE_WEBHOOK_URL not set');
    } else {
      console.log('Forwarded to Make.com', r.statusCode);
    }
  }).catch((e) => {
    console.error('Forwarding failed', e.message || e);
  });

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
