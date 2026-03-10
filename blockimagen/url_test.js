const jwt = require('jsonwebtoken');
require('dotenv').config({ path: 'c:\\Users\\maven\\Desktop\\rewrite\\.env' });

const ak = process.env.KLING_ACCESS_KEY;
const sk = process.env.KLING_SECRET_KEY;

const testApi = async (url, body) => {
    console.log(`\n--- Testing payload on ${url}`);

    // Generate fresh token every time to avoid expiration or reuse issue
    const nowStr = Math.floor(Date.now() / 1000);
    const token = jwt.sign(
        { iss: ak, exp: nowStr + 1800, nbf: nowStr - 5 },
        sk,
        { algorithm: 'HS256', header: { alg: 'HS256', typ: 'JWT' } }
    );

    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    console.log(`Status: ${res.status}`);
    const data = await res.json();
    console.log(`Response: ${JSON.stringify(data, null, 2)}`);
};

(async () => {
    // 1. Test omni-video with image parameter (base64)
    await testApi('https://api.klingai.com/v1/videos/omni-video', {
        model_name: 'kling-video-o1',
        image: 'iBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
        prompt: 'a tiny dot'
    });

    // 2. Test omni-video with missing image parameter
    await testApi('https://api.klingai.com/v1/videos/omni-video', {
        model_name: 'kling-video-o1',
        prompt: 'a tiny dot'
    });
})();
