const jwt = require('jsonwebtoken');

const accessKey = 'AkTeHTrCKbN9ppeJynGBEf3fnpJgtCkE';
const secretKey = 'C8ahBQ3F3kFTTMeArNBLteyrh9hJfKFr';

const payload = {
    iss: accessKey,
    exp: Math.floor(Date.now() / 1000) + (60 * 30),
    nbf: Math.floor(Date.now() / 1000) - 5
};

const token = jwt.sign(payload, secretKey, {
    algorithm: 'HS256',
    header: { alg: 'HS256', typ: 'JWT' }
});

const taskId = '859218962914082883';

Promise.all([
    fetch(`https://api-singapore.klingai.com/v1/videos/image2video/tasks/${taskId}`, { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }).then(r => r.json())
])
    .then(results => {
        console.log('1. /image2video/tasks/', results[0]);
    });
