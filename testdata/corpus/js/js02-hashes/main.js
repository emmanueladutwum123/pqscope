const { createHash } = require('crypto');

createHash('sha256').update('x').digest('hex');
createHash('md5').update('x').digest('hex');
