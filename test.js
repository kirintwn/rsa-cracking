const fs = require('fs');
const ursa = require('ursa');

var privateFilePath = './private3.pem';
var publicFilePath = './publicKeys/public3.pub';

var privateKey = ursa.createPrivateKey(fs.readFileSync(privateFilePath));
var publicKey = ursa.createPublicKey(fs.readFileSync(publicFilePath));

console.log('Encrypt with Public');
var msg = publicKey.encrypt("Everything is going to be 200 OK", 'utf8', 'base64');
console.log('encrypted: ', msg, '\n');

console.log('Decrypt with Private1');
msg = privateKey.decrypt(msg, 'base64', 'utf8');
console.log('decrypted: ', msg, '\n');

console.log('Encrypt with Private (called public)');
msg = privateKey.privateEncrypt("Everything is going to be 200 OK", 'utf8', 'base64');
console.log('encrypted: ', msg, '\n');

console.log('Decrypt with Public (called private)');
msg = publicKey.publicDecrypt(msg, 'base64', 'utf8');
console.log('decrypted: ', msg, '\n');


privateFilePath = './private8.pem';
publicFilePath = './publicKeys/public8.pub';

privateKey = ursa.createPrivateKey(fs.readFileSync(privateFilePath));
publicKey = ursa.createPublicKey(fs.readFileSync(publicFilePath));

console.log('Encrypt with Public');
var msg = publicKey.encrypt("Everything is going to be 200 OK", 'utf8', 'base64');
console.log('encrypted: ', msg, '\n');

console.log('Decrypt with Private1');
msg = privateKey.decrypt(msg, 'base64', 'utf8');
console.log('decrypted: ', msg, '\n');

console.log('Encrypt with Private (called public)');
msg = privateKey.privateEncrypt("Everything is going to be 200 OK", 'utf8', 'base64');
console.log('encrypted: ', msg, '\n');

console.log('Decrypt with Public (called private)');
msg = publicKey.publicDecrypt(msg, 'base64', 'utf8');
console.log('decrypted: ', msg, '\n');
