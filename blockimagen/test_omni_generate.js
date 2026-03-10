const jwt = require('jsonwebtoken');
require('dotenv').config();

const ak = process.env.KLING_ACCESS_KEY;
const sk = process.env.KLING_SECRET_KEY;

const payload = {
    iss: ak,
    exp: Math.floor(Date.now() / 1000) + (60 * 30),
    nbf: Math.floor(Date.now() / 1000) - 5
};

const token = jwt.sign(payload, sk, {
    algorithm: 'HS256',
    header: { alg: 'HS256', typ: 'JWT' }
});

const req1 = fetch('https://api-singapore.klingai.com/v1/videos/image2video', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model_name: 'kling-v3-omni', prompt: 'test a beautiful cat in forest' })
}).then(r => r.json()).then(d => console.log('/image2video returned:', d));

const req2 = fetch('https://api-singapore.klingai.com/v1/videos/omni-video', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model_name: 'kling-v3-omni', prompt: 'test a beautiful dog in forest' })
}).then(r => r.json()).then(d => console.log('/omni-video returned:', d));
