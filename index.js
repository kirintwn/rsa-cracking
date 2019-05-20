const fs = require('fs');
const util = require('util');
const NodeRSA = require('node-rsa');
const { BigInteger } = require('jsbn');

const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);

const BN_1 = new BigInteger('1');

const BNtoBuffer = (BN) => Buffer.from(BN.toString(16), 'hex');

const genPrivKey = (pubKey, gcd) => {
  const { n, e } = pubKey.keyPair;
  const p = gcd.clone();
  const q = pubKey.keyPair.n.divide(gcd);

  if (!pubKey.keyPair.n.equals(p.multiply(q)))
    throw new Error('GCD compute error');

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
  const keyFileArr = await Promise.all(
    new Array(12).fill(null).map(async (el, i) => ({
      name: `public${i + 1}`,
      key: await readFile(`./keys/public${i + 1}.pub`),
    })),
  );

  const privKeys = commonFactorAttack(keyFileArr);
  if (privKeys.length === 0) {
    console.log('No Key Found');
    process.exit(0);
  }

  await Promise.all(
    privKeys.map(async (privKey) => {
      console.log(`Found Key For Public Key: ${privKey.name}.pub`);
      await writeFile(`./keys/${privKey.name}.pem`, privKey.key);
      console.log(`Saved Private Key to File: ${privKey.name}.pem`);
    }),
  );
};

main();
