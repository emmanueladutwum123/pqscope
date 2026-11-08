import { generateKeyPairSync } from 'crypto';

const sig = generateKeyPairSync('ed25519');
const kex = generateKeyPairSync('x25519');
