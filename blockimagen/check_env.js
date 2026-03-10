require('dotenv').config();
console.log('AK length:', process.env.KLING_ACCESS_KEY ? process.env.KLING_ACCESS_KEY.length : 'undefined');
console.log('SK length:', process.env.KLING_SECRET_KEY ? process.env.KLING_SECRET_KEY.length : 'undefined');
console.log('AK raw:', JSON.stringify(process.env.KLING_ACCESS_KEY));
