import { generateKeyPairSync, generateKeyPair } from 'node:crypto';

const kem = generateKeyPairSync('ml-kem-768');
generateKeyPair('ml-dsa-65', (err, pub, priv) => {});
