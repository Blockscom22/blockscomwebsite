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

fetch('https://api.klingai.com/v1/videos/image2video/tasks/859213473137049685', {
    method: 'GET',
    headers: {
        'Authorization': `Bearer ${token}`
    }
})
    .then(res => res.json())
    .then(data => console.log(JSON.stringify(data, null, 2)))
    .catch(err => console.error(err));
