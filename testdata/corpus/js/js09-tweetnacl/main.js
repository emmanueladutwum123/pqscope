const nacl = require('tweetnacl');

const box = nacl.box.keyPair();
const sig = nacl.sign.keyPair();
