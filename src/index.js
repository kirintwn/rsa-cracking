const assert = require('assert');
const path = require('path');
const { promises: fs } = require('fs');
const NodeRSA = require('node-rsa');
const { BigInteger } = require('jsbn');

const KEYS_DIR = '../keys';

const BN_1 = new BigInteger('1');
const BN_0 = new BigInteger('0');
const BNtoBuffer = (BN) => Buffer.from(BN.toString(16), 'hex');

const genPrivKey = (pubKey, gcd) => {
  const { n, e } = pubKey.keyPair;
  assert(n.mod(gcd).equals(BN_0));

  const p = gcd.clone();
  const q = n.divide(gcd);
  const p1 = p.subtract(BN_1);
  const q1 = q.subtract(BN_1);
  const phiN = p1.multiply(q1);
  const d = new BigInteger(e.toString()).modInverse(phiN);
  const dmp1 = d.mod(p1);
  const dmq1 = d.mod(q1);
  const coeff = q.modInverse(p);

  const privKey = new NodeRSA().importKey(
    {
      n: BNtoBuffer(n),
      e,
      d: BNtoBuffer(d),
      p: BNtoBuffer(p),
      q: BNtoBuffer(q),
      dmp1: BNtoBuffer(dmp1),
      dmq1: BNtoBuffer(dmq1),
      coeff: BNtoBuffer(coeff),
    },
    'components',
  );
  return privKey.exportKey('pkcs1-private-pem');
};

const commonFactorAttack = (keyFileArr) => {
  const privKeys = [];
  const pubKeys = keyFileArr.map((el) => new NodeRSA(el.key));

  for (let i = 0; i < pubKeys.length - 1; i += 1) {
    for (let j = i + 1; j < pubKeys.length; j += 1) {
      const GCD = pubKeys[i].keyPair.n.gcd(pubKeys[j].keyPair.n);
      if (!GCD.equals(BN_1)) {
        privKeys.push({
          name: `${keyFileArr[i].name}`,
          key: genPrivKey(pubKeys[i], GCD),
        });
        privKeys.push({
          name: `${keyFileArr[j].name}`,
          key: genPrivKey(pubKeys[j], GCD),
        });
      }
    }
  }
  return privKeys;
};

const main = async () => {
  try {
    const keyFileArr = await Promise.all(
      new Array(12).fill(null).map(async (el, i) => ({
        name: `public${i + 1}`,
        key: await fs.readFile(
          path.join(__dirname, `${KEYS_DIR}/public${i + 1}.pub`),
        ),
      })),
    );

    const privKeys = commonFactorAttack(keyFileArr);
    assert(privKeys.length > 0);

    await Promise.all(
      privKeys.map(async (privKey) => {
        console.log(`Found Key For Public Key: ${privKey.name}.pub`);
        console.log(`Saving Private Key to File: ${privKey.name}.pem`);
        return fs.writeFile(
          path.join(__dirname, `${KEYS_DIR}/${privKey.name}.pem`),
          privKey.key,
        );
      }),
    );

    return privKeys.map((key) => key.name);
  } catch (error) {
    console.error(error.message);
    return [];
  }
};

if (!module.parent) {
  main();
}

module.exports = main;
