import crypto from 'node:crypto';

const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
