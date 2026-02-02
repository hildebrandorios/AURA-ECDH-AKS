import { ec as EC } from 'elliptic';
import { v4 as uuidv4, validate as uuidValidate } from 'uuid';

const ec = new EC('secp256k1');

console.log("Starting Verification...");

// 1. Verify UUID Logic
const id = uuidv4();
if (!uuidValidate(id)) {
    console.error("UUID Validation Failed");
    process.exit(1);
}
console.log("UUID Logic: OK");

// 2. Verify SECP256K1 Logic
try {
    const key = ec.genKeyPair();
    const pub = key.getPublic(true, 'hex');
    const priv = key.getPrivate('hex');

    console.log("Generated KeyPair OK");
    console.log("Public:", pub);

    // Validate
    const keyFromPub = ec.keyFromPublic(pub, 'hex');
    if (!keyFromPub.validate().result) {
        console.error("Public Key Validation Failed");
        process.exit(1);
    }
    console.log("Key Validation: OK");

    // ECDH
    const otherKey = ec.genKeyPair();
    const derived1 = key.derive(otherKey.getPublic()).toString(16);
    const derived2 = otherKey.derive(key.getPublic()).toString(16);

    if (derived1 !== derived2) {
        console.error("ECDH Mismatch!");
        console.error(derived1);
        console.error(derived2);
        process.exit(1);
    }
    console.log("ECDH Logic: OK");

} catch (e) {
    console.error("Crypto Error", e);
    process.exit(1);
}

console.log("ALL CHECKS PASSED");
