const crypto = { createHash: (a) => a };
crypto.createHash('md5');
const myLib = require('./hashing');
myLib.createHash('sha1');
