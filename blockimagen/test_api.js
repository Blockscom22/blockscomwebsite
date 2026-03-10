const jwt = require('jsonwebtoken');
require('dotenv').config();

const ak = process.env.KLING_ACCESS_KEY;
const sk = process.env.KLING_SECRET_KEY;

const tinyImage = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

const createToken = () => {
    const payload = {
        iss: ak,
        exp: Math.floor(Date.now() / 1000) + (60 * 30),
        nbf: Math.floor(Date.now() / 1000) - 5
    };
    return jwt.sign(payload, sk, { algorithm: 'HS256', header: { alg: 'HS256', typ: 'JWT' } });
};

const testApi = async (url, body) => {
    console.log(`Testing payload on ${url}`);
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${createToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    console.log(`Status: ${res.status}`);
    const data = await res.json();
    console.log(`Response: ${JSON.stringify(data, null, 2)}`);
};

(async () => {
    // Test base API logic
    await testApi('https://api.klingai.com/v1/videos/image2video', {
        model_name: 'kling-v2-6',
        image: tinyImage,
        image_tail: tinyImage,
        mode: 'pro',
        prompt: 'a tiny dot',
        aspect_ratio: "1:1"
    });
})();
