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

const taskId = '859227647396675629';

const urls = [
    `https://api-singapore.klingai.com/v1/videos/omni-video/tasks/${taskId}`,
    `https://api-singapore.klingai.com/v1/videos/omni-video/${taskId}`
];

Promise.all(urls.map(url => fetch(url, { headers: { 'Authorization': `Bearer ${token}` } }).then(async r => ({ url, status: r.status, data: await r.text() }))))
    .then(r => console.log(JSON.stringify(r, null, 2)));
