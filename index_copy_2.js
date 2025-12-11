require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());

function getPrivateKey() {
    const rawEnv = process.env.WA_FLOW_PRIVATE_KEY;
    const path = process.env.WA_FLOW_PRIVATE_KEY_PATH;
    const raw = rawEnv || (path ? fs.readFileSync(path, 'utf8') : '');
    if (!raw) throw new Error('Missing PRIVATE_KEY');
    if (/BEGIN [A-Z ]+PRIVATE KEY/.test(raw)) return raw;
    const type = (process.env.WA_FLOW_PRIVATE_KEY_TYPE || 'pkcs8').toLowerCase();
    const header = type === 'pkcs1' ? '-----BEGIN RSA PRIVATE KEY-----\n' : '-----BEGIN PRIVATE KEY-----\n';
    const footer = type === 'pkcs1' ? '\n-----END RSA PRIVATE KEY-----' : '\n-----END PRIVATE KEY-----';
    const body = raw.replace(/\s+/g, '').match(/.{1,64}/g).join('\n');
    return header + body + footer;
}

function normalizeB64(s) {
    if (!s || typeof s !== 'string') return s;
    let t = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const m = t.length % 4;
    if (m === 2) t += '==';
    else if (m === 3) t += '=';
    else if (m === 1) t += '===';
    return t;
}

function decryptAesKey(encryptedAesKeyB64, privateKeyPem) {
    const enc = Buffer.from(normalizeB64(encryptedAesKeyB64), 'base64');
    const pass = process.env.WA_FLOW_PRIVATE_KEY_PASSPHRASE;
    const opt256 = pass ? { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', passphrase: pass } : { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };
    const opt1 = pass ? { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1', passphrase: pass } : { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' };
    let key;
    try {
        key = crypto.privateDecrypt(opt256, enc);
    } catch (_) {
        key = crypto.privateDecrypt(opt1, enc);
    }
    if (![16, 24, 32].includes(key.length)) {
        const asText = key.toString('utf8').trim();
        try {
            const maybe = Buffer.from(normalizeB64(asText), 'base64');
            if ([16, 24, 32].includes(maybe.length)) return maybe;
        } catch {}
    }
    return key;
}

function decryptFlowData(encryptedFlowDataB64, aesKey, iv) {
    const enc = Buffer.from(normalizeB64(encryptedFlowDataB64), 'base64');
    const algo = aesKey.length === 32 ? 'aes-256-cbc' : 'aes-128-cbc';
    const decipher = crypto.createDecipheriv(algo, aesKey, iv);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return dec.toString('utf8');
}

function encryptFlowData(plaintext, aesKey, iv) {
    const algo = aesKey.length === 32 ? 'aes-256-cbc' : 'aes-128-cbc';
    const cipher = crypto.createCipheriv(algo, aesKey, iv);
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
        console.log({aesKey});
        if (![16, 24, 32].includes(aesKey.length)) return res.sendStatus(400);
        const iv = Buffer.from(normalizeB64(initial_vector), 'base64');
        if (iv.length !== 16) return res.sendStatus(400);
        console.log({ encrypted_flow_data, aesKeyLength: aesKey.length, privateKeyPem });
        let decrypted;
        try {
            decrypted = decryptFlowData(encrypted_flow_data, aesKey, iv);
        } catch (err) {
            console.log(err);
            return res.status(400).json(err);
        }
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
