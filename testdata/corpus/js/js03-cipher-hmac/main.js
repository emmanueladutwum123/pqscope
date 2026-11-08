const crypto = require('crypto');

const alg = 'aes-256-gcm';
const c = crypto.createCipheriv(alg, key, iv);
const m = crypto.createHmac('sha1', key);
