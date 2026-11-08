import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';

const a = ed25519.utils.randomSecretKey();
const b = x25519.utils.randomSecretKey();
const c = p256.utils.randomSecretKey();
