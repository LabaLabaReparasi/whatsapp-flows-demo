// Load environment config and core deps
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");

const PORT = 3000;
const app = express();

// Parse JSON body for Flows requests
app.use(express.json({ limit: "1mb" }));

// RSA private key used to unwrap AES key (ensure it matches Meta-uploaded public key)
const PRIVATE_KEY = process.env.WA_FLOW_PRIVATE_KEY.replace(/\\n/g, "\n");
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL || "";

// Ensure a value is an array (supports comma-separated strings)
function ensureArray(v) {
    if (Array.isArray(v)) return v;
    if (typeof v === "string") return v.split(",").map((s) => s.trim()).filter(Boolean);
    return v != null ? [v] : [];
}

// Build Make.com payload from decrypted flow data
// function buildMakePayload(data) {
function buildMakePayload(data) {

    const src = (data && (data.payload || data.data || (data.action && data.action.payload))) || data || {};
    const name = src.name || src.full_name || src.nama || "";
    const phone = src.phone || src.telephone || src.msisdn || src.whatsapp || "";
    const domisili = src.domisili || src.city || src.location || "";
    const jumlah_barang = (src.jumlah_barang || src.quantity || src.qty || "").toString();
    const tipe_barang_raw = src.tipe_barang || src.items || src.tipe || src.item_type || [];
    const tipe_barang = ensureArray(tipe_barang_raw);
    const jenis_kerusakan = src.jenis_kerusakan || src.damage || src.issue || "";
    const pickup = (src.pickup || src.pick_up || src.is_pickup || "").toString();
    const screen_id = (data && (data.screen_id || data.screenId || (data.screen && data.screen.id))) || "ORDER_FORM";
    return {
        version: "3.0",
        screen_id,
        action: {
            name: "complete",
            payload: { name, phone, domisili, jumlah_barang, tipe_barang, jenis_kerusakan, pickup }
        }
    };
}

// Build WhatsApp Flows endpoint response based on decrypted request
function buildServerResponse(decrypted) {
    /*
    Request body dari meta
    // Request body before decryption
    {
        "encrypted_flow_data": "SH16...P9LU=",
        "encrypted_aes_key": "wXO2O...lLug==",
        "initial_vector": "Grws...4MiA=="
    }

    // Decrypted request body when flow is launched
    {
        "action": "INIT",
        "flow_token": "<Flow token from the flow message>",
        "version": "3.0"
    }

    // Decrypted request body for data_exchange action (eg: footer press)
    {
        "action": "data_exchange",
        "screen": "<CURRENT_SCREEN_ID>",
        "data": {
            "some_param": "some value from action payload (string, boolean, or number)"
        },
        "flow_token": "<Flow token from the flow message>",
        "version": "3.0"
    }

    // Decrypted request body when back button is pressed
    {
        "action": "BACK",
        "screen": "<CURRENT_SCREEN_ID>",
        "flow_token": "<Flow token from the flow message>",
        "version": "3.0"
    }
    */

    const version = decrypted.version || "3.0";
    const screenId = decrypted.screen_id || "ORDER_FORM";
    const rawAction = decrypted.action.toLowerCase() || "ping";
    const flowToken = process.env.WA_FLOW_TOKEN;

    console.log({ rawAction });

    if (rawAction === "init" || rawAction === "back") {
        return {
            ORDER_FORM: {
                "screen": "ORDER_FORM",
                "data": {}
            },
            SUCCESS: {
                "screen": "SUCCESS",
                "data": {
                    "extension_message_response": {
                        "params": {
                            "flow_token": flowToken,
                            // "some_param_name": "PASS_CUSTOM_VALUE"
                        }
                    }
                }
            },
        };
    }
    else if (rawAction === "data_exchange") {
        return {
            "screen": "SUCCESS",
            "data": {
                "extension_message_response": {
                    "params": {
                        "flow_token": flowToken,
                        // "optional_param1": "<value1>",
                        // "optional_param2": "<value2>"
                    }
                }
            }
        };
    }

    return { "data": { "status": "active" } };
}
// Forward decrypted payload to Make.com webhook (non-blocking)
function forwardToMake(payload) {
    if (!MAKE_WEBHOOK_URL) return Promise.resolve({ skipped: true });
    const url = new URL(MAKE_WEBHOOK_URL);
    const data = JSON.stringify(payload);
    const isHttps = url.protocol === "https:";
    const mod = isHttps ? require("https") : require("http");
    const options = {
        method: "POST",
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(data)
        }
    };
    return new Promise((resolve, reject) => {
        const req = mod.request(options, (res) => {
            const chunks = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString() }));
        });
        req.on("error", reject);
        req.write(data);
        req.end();
    });
}

// Health check endpoint
app.get("/health", (req, res) => {
    res.status(200).send("OK");
});

// Main Flows endpoint: decrypt -> forward to Make -> encrypt response
app.post("/flow", async (req, res) => {
    const payload = Array.isArray(req.body) ? req.body[0] : req.body;
    console.log(payload);
    try {
        const { decryptedBody, aesKeyBuffer, initialVectorBuffer, mode } =
            decryptRequest(payload, PRIVATE_KEY);
        console.log(makePayload);

        // Send to Make.com asynchronously (mapped payload) if the action is "data_exchange"
        if (decryptedBody.action === "data_exchange") {
            // const makePayload = buildMakePayload(decryptedBody);
            const makePayload = decryptedBody;
            await forwardToMake(makePayload)
        }
        const serverResponse = buildServerResponse(decryptedBody);
        console.log({ serverResponse });
        // MUST RETURN ONLY BASE64 TEXT
        const encryptedResponse = encryptResponse(
            serverResponse,
            aesKeyBuffer,
            initialVectorBuffer,
            mode
        );
        res.status(200).type("text/plain").send(encryptedResponse);
    } catch (err) {
        console.error("DECRYPT ERROR:", err);
        res.status(500).send("Failed to decrypt request");
    }
});

// Decrypt incoming request
// - RSA-OAEP (SHA-256) unwraps AES key
// - Try AES-GCM first (ciphertext|authTag), fallback to AES-CBC
function decryptRequest(payload, privateKeyPem) {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = payload;

    if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
        throw new Error("Missing fields in payload");
    }

    // Decrypt AES key using RSA private key (OAEP-SHA256)
    const aesKeyBuffer = crypto.privateDecrypt(
        {
            key: privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, "base64")
    );

    const encryptedBuffer = Buffer.from(encrypted_flow_data, "base64");
    const iv = Buffer.from(initial_vector, "base64");
    const keyLen = aesKeyBuffer.length;
    let decryptedJSON;
    let mode = "gcm";
    try {
        // Attempt AES-GCM (last 16 bytes are auth tag)
        const TAG_LENGTH = 16;
        const ciphertext = encryptedBuffer.subarray(0, -TAG_LENGTH);
        const authTag = encryptedBuffer.subarray(-TAG_LENGTH);
        const algoGcm = keyLen === 32 ? "aes-256-gcm" : "aes-128-gcm";
        const decipher = crypto.createDecipheriv(algoGcm, aesKeyBuffer, iv);
        decipher.setAuthTag(authTag);
        decryptedJSON = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
        mode = "gcm";
    } catch (_) {
        // Fallback AES-CBC (PKCS#7 padding)
        const algoCbc = keyLen === 32 ? "aes-256-cbc" : "aes-128-cbc";
        const decipherCbc = crypto.createDecipheriv(algoCbc, aesKeyBuffer, iv);
        decryptedJSON = Buffer.concat([decipherCbc.update(encryptedBuffer), decipherCbc.final()]).toString("utf8");
        mode = "cbc";
    }

    return {
        decryptedBody: JSON.parse(decryptedJSON),
        /* The output should be like this
        {
            "version": "3.0",
            "screen_id": "ORDER_FORM",
            "action": {
                "name": "complete",
                "payload": {
                    "name": "John Doe",
                    "phone": "+628123456789",
                    "domisili": "jaksel",
                    "jumlah_barang": "3",
                    "tipe_barang": ["koper", "tas"],
                    "jenis_kerusakan": "Roda patah",
                    "pickup": "yes"
                }
            }
        }
        */
        aesKeyBuffer,
        initialVectorBuffer: iv,
        mode,
    };
}

// Encrypt response using same mode detected in request
function encryptResponse(responseObj, aesKeyBuffer, iv, mode = "gcm") {
    const plaintext = JSON.stringify(responseObj);
    const keyLen = aesKeyBuffer.length;

    // REQUIRED BY META → flip all IV bytes (bitwise NOT)
    const flippedIv = Buffer.from(iv.map(b => (~b & 0xff)));

    if (mode === "cbc") {
        const algoCbc = keyLen === 32 ? "aes-256-cbc" : "aes-128-cbc";
        const cipher = crypto.createCipheriv(algoCbc, aesKeyBuffer, flippedIv);
        const encrypted = Buffer.concat([
            cipher.update(Buffer.from(plaintext, "utf8")),
            cipher.final()
        ]);
        return encrypted.toString("base64");
    }

    // GCM
    const algoGcm = keyLen === 32 ? "aes-256-gcm" : "aes-128-gcm";
    const cipher = crypto.createCipheriv(algoGcm, aesKeyBuffer, flippedIv);
    const encrypted = Buffer.concat([
        cipher.update(Buffer.from(plaintext, "utf8")),
        cipher.final()
    ]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([encrypted, authTag]).toString("base64");
}


app.listen(PORT, () => {
    console.log("WhatsApp Flows server running on port " + PORT);
});
