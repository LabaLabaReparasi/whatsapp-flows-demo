require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());

function getPrivateKey() {
    let privateKey = process.env.WA_FLOW_PRIVATE_KEY;

    if (!privateKey) throw new Error('Missing PRIVATE_KEY or PRIVATE_KEY_PATH');
    return "-----BEGIN RSA PRIVATE KEY-----\n" +
        privateKey.match(/.{1,64}/g).join("\n") +
        "\n-----END RSA PRIVATE KEY-----";
}

function decryptAesKey(encryptedAesKeyB64, privateKeyPem) {
    const enc = Buffer.from(encryptedAesKeyB64, 'base64');
    return crypto.privateDecrypt({
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, enc);
}

function decryptFlowData(encryptedFlowDataB64, aesKey, iv) {
    const enc = Buffer.from(encryptedFlowDataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return dec.toString('utf8');
}

function encryptFlowData(plaintext, aesKey, iv) {
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    const enc = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
    return enc.toString('base64');
}

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

app.post('/flow', (req, res) => {
    try {
        const payload = Array.isArray(req.body) ? req.body[0] : req.body;
        const { encrypted_flow_data, encrypted_aes_key, initial_vector } = payload || {};
        if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) return res.sendStatus(400);

        const privateKeyPem = getPrivateKey();
        const aesKey = decryptAesKey(encrypted_aes_key, privateKeyPem);
        if (aesKey.length !== 16) return res.sendStatus(400);
        const iv = Buffer.from(initial_vector, 'base64');
        if (iv.length !== 16) return res.sendStatus(400);

        const decrypted = decryptFlowData(encrypted_flow_data, aesKey, iv);
        let data;
        console.log({ data, "message": "Decrypted flow data" });
        try { data = JSON.parse(decrypted); } catch { data = { raw: decrypted }; }
        console.log({ data, "message": "After check flow data" });

        forwardToMake(data).then((r) => {
            if (r && r.skipped) console.warn('MAKE_WEBHOOK_URL not set');
        }).catch((e) => {
            console.error(e && e.message ? e.message : e);
        });

        const responsePayload = JSON.stringify({ ok: true, data });
        const encryptedResponseB64 = encryptFlowData(responsePayload, aesKey, iv);
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponseB64);
    } catch (e) {
        console.error(e && e.message ? e.message : e);
        res.sendStatus(500);
    }
});

app.get('/', (req, res) => res.send('OK'));

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log("Server run on port", port);
});
