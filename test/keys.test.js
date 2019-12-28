const path = require('path');
const { promises: fs } = require('fs');
const NodeRSA = require('node-rsa');
const attack = require('../src/index');

const KEYS_DIR = '../keys';

test('All key pairs works', async () => {
  const keyNames = await attack();

  expect(keyNames.length).toBeGreaterThan(0);

  await Promise.all(
    keyNames.map(async (name) => {
      const [pubFile, privFile] = await Promise.all([
        fs.readFile(path.join(__dirname, `${KEYS_DIR}/${name}.pub`)),
        fs.readFile(path.join(__dirname, `${KEYS_DIR}/${name}.pem`)),
      ]);
      const pubKey = new NodeRSA(pubFile);
      const privKey = new NodeRSA(privFile);

      const msg = 'testMsg 001!%$@@@*';

      const encryptedData = privKey.encryptPrivate(msg, 'base64', 'utf8');
      const decryptedMsg = pubKey.decryptPublic(encryptedData, 'utf8');

      expect(msg).toEqual(decryptedMsg);
    }),
  );
});
