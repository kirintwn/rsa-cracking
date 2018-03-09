const fs = require('fs');
const ursa = require('ursa');
const bigInt = require('big-integer');

var RSAdata = [13];
/*
    publicKey
    privateKey
    exponent
    modulus
    d
    prime[2]
    isDone
*/

var printRSAdata_isDone = (i) => {
    if(RSAdata[i].isDone == 1) {
        console.log("RSAdata" , i);
        console.log("exponent:" , RSAdata[i].exponent.toString() , "\n");
        console.log("modulus:" , RSAdata[i].modulus.toString() , "\n");
        console.log("d:" , RSAdata[i].d.toString() , "\n");
        console.log("prime0:" , RSAdata[i].prime[0].toString() , "\n");
        console.log("prime1:" , RSAdata[i].prime[1].toString() , "\n");
    }
}

var readPublicPEM = () => {
    for (var i = 1 ; i <= 12 ; i++) {
        var tempFilePath = './publicKeys/public' + i.toString() + '.pub';
        var tempPublicKey = ursa.createPublicKey(fs.readFileSync(tempFilePath));

        var tempExponent_HEX = tempPublicKey.getExponent('hex');
        var tempExponent = new bigInt(tempExponent_HEX , 16);

        var tempModulus_HEX = tempPublicKey.getModulus('hex');
        var tempModulus = new bigInt(tempModulus_HEX , 16);

        var tempRSAdata = {
            publicKey: tempPublicKey,
            privateKey: new Buffer(10000),
            exponent: tempExponent,
            modulus: tempModulus,
            d: new bigInt("0" , 10),
            prime: [-1 , -1],
            isDone: 0
        }
        RSAdata[i] = tempRSAdata;
    }
}

var findPrime = () => {
    for (var i = 1 ; i <= 12 ; i++) {
        for (var j = i+1 ; j <=12 ; j++) {
            var tempGCD = bigInt.gcd(RSAdata[i].modulus , RSAdata[j].modulus);
            if(tempGCD > 1) {
                var tempPrime_i = bigInt(RSAdata[i].modulus).divmod(tempGCD).quotient;
                var tempPrime_j = bigInt(RSAdata[j].modulus).divmod(tempGCD).quotient;
                RSAdata[i].prime = [tempGCD , tempPrime_i];
                RSAdata[j].prime = [tempGCD , tempPrime_j];
                RSAdata[i].isDone = 1;
                RSAdata[j].isDone = 1;
            }
        }
    }
}

var genPrivateKey = () => {
    for (var i = 1 ; i <= 12 ; i++) {
        if(RSAdata[i].isDone == 1) {
            var temp_p = RSAdata[i].prime[0];
            var temp_q = RSAdata[i].prime[1];
            var temp_p1 = temp_p.minus(1);
            var temp_q1 = temp_q.minus(1);

            var temp_phiN = bigInt(temp_p1).multiply(temp_q1);

            var temp_e = RSAdata[i].exponent;
            var temp_m = RSAdata[i].modulus;
            var temp_d = bigInt(temp_e).modInv(temp_phiN);

            var temp_dp = bigInt(temp_d).mod(temp_p1);
            var temp_dq = bigInt(temp_d).mod(temp_q1);
            var temp_invQ = bigInt(temp_q).modInv(temp_p);

            var buf_m = Buffer.from(temp_m.toString(16) , "hex");
            var buf_e = Buffer.from(temp_e.toString(16) , "hex");
            var buf_p = Buffer.from(temp_p.toString(16) , "hex");
            var buf_q = Buffer.from(temp_q.toString(16) , "hex");
            var buf_dp = Buffer.from(temp_dp.toString(16) , "hex");
            var buf_dq = Buffer.from(temp_dq.toString(16) , "hex");
            var buf_invQ = Buffer.from(temp_invQ.toString(16) , "hex");
            var buf_d = Buffer.from(temp_d.toString(16) , "hex");

            RSAdata[i].d = temp_d;
            RSAdata[i].privateKey = ursa.createPrivateKeyFromComponents(buf_m , buf_e , buf_p , buf_q , buf_dp , buf_dq , buf_invQ , buf_d);

            var tempPEM = RSAdata[i].privateKey.toPrivatePem('utf8');
            var tempFilePath = './private' + i.toString() + '.pem';
            fs.writeFileSync(tempFilePath , tempPEM);
            console.log(tempPEM);
        }
    }
}

readPublicPEM();
findPrime();
genPrivateKey();
