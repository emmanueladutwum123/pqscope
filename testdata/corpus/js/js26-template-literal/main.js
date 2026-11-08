const crypto = require('crypto');

const bits = 256;
const h = crypto.createHash(`sha${bits}`);
