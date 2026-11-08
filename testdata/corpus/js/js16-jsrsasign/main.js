const { KEYUTIL } = require('jsrsasign');

const kp = KEYUTIL.generateKeypair('EC', 'secp256r1');
