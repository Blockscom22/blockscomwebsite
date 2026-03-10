const jwt = require('jsonwebtoken');

const ak = 'AkTeHTrCKbN9ppeJynGBEf3fnpJgtCkE';
const sk = 'C8ahBQ3F3kFTTMeArNBLteyrh9hJfKFr';

const payload = {
    iss: ak,
    exp: Math.floor(Date.now() / 1000) + (60 * 30),
    nbf: Math.floor(Date.now() / 1000) - 5
};

const token = jwt.sign(payload, sk, {
    algorithm: 'HS256',
    header: { alg: 'HS256', typ: 'JWT' }
});

const urls = [
    `https://api-singapore.klingai.com/v1/videos/image2video/859221015874895961`,
    `https://api-singapore.klingai.com/v1/videos/omni-video/859227647396675629`,
    `https://api-singapore.klingai.com/v1/videos/image2video/859227647396675629`
];

Promise.all(urls.map(url => fetch(url, { headers: { 'Authorization': `Bearer ${token}` } }).then(async r => ({ url, status: r.status, data: await r.text() }))))
    .then(r => console.log(JSON.stringify(r, null, 2)));
