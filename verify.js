const fs = require('fs');
const util = require('util');
const NodeRSA = require('node-rsa');

const readFile = util.promisify(fs.readFile);

const checkKeyPairs = (pubKey, privKey) => {
  const msg = 'testMsg 001!';

  let encryData = privKey.encryptPrivate(msg, 'base64', 'utf8');
  let decryptData = pubKey.decryptPublic(encryData, 'utf8');
  if (decryptData !== msg) return false;

  encryData = pubKey.encrypt(msg, 'base64', 'utf8');
  decryptData = privKey.decrypt(encryData, 'utf8');
  if (decryptData !== msg) return false;

  return true;
};

const main = async (names) => {
  try {
    await Promise.all(
      names.map(async (name) => {
        const [pubFile, privFile] = await Promise.all([
          readFile(`./keys/${name}.pub`),
          readFile(`./keys/${name}.pem`),
        ]);
        const pubKey = new NodeRSA(pubFile);
        const privKey = new NodeRSA(privFile);
        console.log(
          `Key Pair ${
            checkKeyPairs(pubKey, privKey)
              ? `Passed: ${name}`
              : `Failed: ${name}`
          }`,
        );
      }),
    );
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
};

main(['public3', 'public8']);
