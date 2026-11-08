const forge = require('node-forge');

const pair = forge.pki.rsa.generateKeyPair({ bits: 3072 });
const md = forge.md.sha1.create();
