# RSA Cracking
>Implementation of the well-known RSA cracking tech, Common Factor Attacks.

## Tech
- Using `Node.js` to implement `Common Factor Attacks` 
- Big Number Computation
- RSA key generation and restoration

## Procedure and Mathematical Computation
- Collect enough quantity of RSA public keys

- Import all public key files
   - extract and stroe their modulus and exponent value

- The value is in the big number form (supported by jsbn)

- Traversal all the possible combination of 12 `modulus` value 
   - to see if there exist a GCD greater then 1

- Store the GCD `p` and the other factor `q` of the two modulus respectively

```
Calculate φ( n ) = (p-1)*(q-1)
Calculate d = e modinverse φ( n )
Calculate dp = d mod (p-1)
Calculate dq = d mod (q-1)
Calculate coeff (A.K.A. invQ) = q modinverse p
Generate private key with modulus, exponent, p, q, dp, dq, invQ and d
Export the private key to pem form
```

## Dependencies
* jsbn: `^1.1.0`
* node-rsa: `^1.0.5`

## Usage
```
npm install
node index.js
```
