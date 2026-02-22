require('dotenv').config();
const crypto = require('crypto');

const ENC_KEY = crypto.createHash('sha256').update(process.env.TOKEN_ENCRYPTION_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || 'blockscom-default-key').digest();

function decryptSecret(value) {
    if (!String(value).startsWith('enc:')) return String(value);
    try {
        const parts = String(value).split(':');
        const [, ivB64, tagB64, dataB64] = parts;
        const iv = Buffer.from(ivB64, 'base64');
        const tag = Buffer.from(tagB64, 'base64');
        const data = Buffer.from(dataB64, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
        decipher.setAuthTag(tag);
        const dec = Buffer.concat([decipher.update(data), decipher.final()]);
        return dec.toString('utf8');
    } catch (err) {
        return 'DECRYPTION_FAILED: ' + err.message;
    }
}

const key = "enc:REPLACE_WITH_YOUR_ENCRYPTED_VALUE_FOR_TESTING";
console.log("TEST RESULT:", decryptSecret(key));
