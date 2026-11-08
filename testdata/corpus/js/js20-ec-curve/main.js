const crypto = require('crypto');

const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
