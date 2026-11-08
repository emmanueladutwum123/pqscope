import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 as dsa } from '@noble/post-quantum/ml-dsa.js';

const k = ml_kem768.keygen();
const s = dsa.keygen();
