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

const fakeTaskId = '859221015874895961';

const urls = [
    `https://api-singapore.klingai.com/v1/videos/image2video/tasks/${fakeTaskId}`,
    `https://api.klingai.com/v1/videos/image2video/tasks/${fakeTaskId}`,
    `https://api-singapore.klingai.com/v1/videos/image2video/${fakeTaskId}`,
    `https://api.klingai.com/v1/videos/image2video/${fakeTaskId}`
];

Promise.all(urls.map(url => fetch(url, { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } })
    .then(async r => {
        let body = await r.text();
        return { url: url, status: r.status, data: body };
    })))
    .then(results => console.log(JSON.stringify(results, null, 2)));
