import pkg from 'elliptic';
const { ec: EC } = pkg;
import * as nodeCrypto from 'crypto';
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import { Encoding, CRYPTO, CryptoCurve } from '../src/config/constants';

const ec = new EC(CryptoCurve.SECP256K1);

const SERVER_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJVond8ty13vMS9XyEVu
/LQ8okK3OzH/FHzQfsOI1x+bKFyL+uXSg/sTTboBbohQaqvn/podnXzzlwG5htAS
9nwhYB/DUf7JJfmlgUw+99etXbgv52DUR4GEEoId092giNWIyLPPD3hkaelAwGUp
T4QT0aBGa2bOeoSNydHXK12SETdLYaI5nbQzvwHrHo4EkUlkAm4MivLD5gjCGO8s
qEkFMOl/6srYw24HPVTLu5ltBe+Dyk8oeiDMpFoZWlo0I/AyRJAdQCMvD2MDd4s4
ikJLwI37pQeZjEqWnC3oh3xv7hysZ88V4URZmpK8BhLFMbt0TEpwwEWpCIUiNF/c
EQIDAQAB
-----END PUBLIC KEY-----`;

async function runDemo() {
    const baseUrl = 'http://localhost:3000/api';
    const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
    const deviceId = uuidv5(uuidv4(), NAMESPACE);

    console.log('\x1b[1m%s\x1b[0m', `>>> INICIANDO DEMO V9 EN: ${baseUrl}`);
    console.log(`Dispositivo: ${deviceId}\n`);

    const encryptRSAPublic = (publicKey: string, data: string) => {
        return nodeCrypto.publicEncrypt({
            key: publicKey,
            padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: CRYPTO.HASH_ALGORITHM
        }, Buffer.from(data, Encoding.UTF8)).toString(Encoding.BASE64);
    };

    const decryptRSAPublic = (publicKey: string, base64: string) => {
        return nodeCrypto.publicDecrypt({
            key: publicKey,
            padding: nodeCrypto.constants.RSA_PKCS1_PADDING
        }, Buffer.from(base64, Encoding.BASE64)).toString(Encoding.UTF8);
    };

    const encryptAES = (key: Buffer, plaintext: string) => {
        const iv = nodeCrypto.randomBytes(CRYPTO.IV_BYTES);
        const cipher = nodeCrypto.createCipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
        let payload = cipher.update(plaintext, Encoding.UTF8);
        payload = Buffer.concat([payload, cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, payload]).toString(Encoding.BASE64);
    };

    const decryptAES = (key: Buffer, base64: string) => {
        const buffer = Buffer.from(base64, Encoding.BASE64);
        const iv = buffer.subarray(0, CRYPTO.IV_BYTES);
        const tag = buffer.subarray(CRYPTO.IV_BYTES, CRYPTO.IV_BYTES + CRYPTO.TAG_BYTES);
        const payload = buffer.subarray(CRYPTO.IV_BYTES + CRYPTO.TAG_BYTES);
        const decipher = nodeCrypto.createDecipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
        decipher.setAuthTag(tag);
        let decrypted = decipher.update(payload, undefined, Encoding.UTF8);
        decrypted += decipher.final(Encoding.UTF8);
        return decrypted;
    };

    // --- [1] HANDSHAKE ---
    console.log('\x1b[36m%s\x1b[0m', '--- [1] INICIANDO HANDSHAKE ---');

    const clientPrimary = ec.genKeyPair();
    const pubPrimaryHex = clientPrimary.getPublic(true, Encoding.HEX);

    const hsRequest = {
        deviceId,
        publicKeyPrimary: encryptRSAPublic(SERVER_RSA_PUBLIC_KEY, pubPrimaryHex)
    };

    console.log('\x1b[33m%s\x1b[0m', '>> REQUEST HANDSHAKE:');
    console.log(JSON.stringify(hsRequest, null, 2));

    const hsResponse = await fetch(`${baseUrl}/httpTriggerHandsheck`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hsRequest)
    });

    const hsData = await hsResponse.json();
    if (!hsResponse.ok) throw new Error(`Handshake failed: ${JSON.stringify(hsData)}`);

    console.log('\x1b[32m%s\x1b[0m', '<< RESPONSE HANDSHAKE:');
    console.log(JSON.stringify(hsData, null, 2));

    console.log('\x1b[32m%s\x1b[0m', '<< HANDSHAKE EXITOSO. KID:', hsData.kid);

    const backendPubHex = decryptRSAPublic(SERVER_RSA_PUBLIC_KEY, hsData.publicKeyPrimary);
    const backendEphHex = decryptRSAPublic(SERVER_RSA_PUBLIC_KEY, hsData.publicKeyEphemeral);

    const ssP = Buffer.from(clientPrimary.derive(ec.keyFromPublic(backendPubHex, Encoding.HEX).getPublic()).toArray('be', 32));

    // --- [2] PROCESS REQUEST ---
    console.log('\n\x1b[36m%s\x1b[0m', '--- [2] ENVIANDO PETICIÓN PROCESS ---');

    // Generar claves efímeras X25519 (Igual que en performance-test.ts)
    const clientEphPair = nodeCrypto.generateKeyPairSync(CryptoCurve.X25519);
    const clientEphHex = Buffer.from((clientEphPair.publicKey.export({ format: 'jwk' }) as any).x, Encoding.BASE64URL).toString(Encoding.HEX);

    // Cifrar clave efímera con ssP (Primary Secret)
    const encClientEph = encryptAES(ssP, clientEphHex);

    // Backend Ephemeral Public Key para derivar ssE
    const backendEphPubKey = nodeCrypto.createPublicKey({
        key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(backendEphHex, Encoding.HEX).toString(Encoding.BASE64URL) },
        format: 'jwk'
    });

    const ssE = nodeCrypto.diffieHellman({
        privateKey: clientEphPair.privateKey,
        publicKey: backendEphPubKey
    });

    const km = nodeCrypto.hkdfSync(CRYPTO.HASH_ALGORITHM, Buffer.concat([ssP, ssE]), Buffer.from(deviceId), CRYPTO.HKDF_INFO_MESSAGE, 32);
    const kmBuffer = Buffer.from(km);

    const payload = JSON.stringify({ message: "Hello from Client", ts: Date.now() });
    const encData = encryptAES(kmBuffer, payload);

    const processRequest = {
        deviceId,
        kid: hsData.kid,
        publicKeyEphemeral: encClientEph,
        encryptedData: encData
    };

    console.log('\x1b[33m%s\x1b[0m', '>> REQUEST PROCESS:');
    console.log(JSON.stringify(processRequest, null, 2));

    const procResponse = await fetch(`${baseUrl}/httpTriggerProcess`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(processRequest)
    });

    const procData = await procResponse.json();
    if (!procResponse.ok) throw new Error(`Process failed: ${JSON.stringify(procData)}`);

    console.log('\x1b[32m%s\x1b[0m', '<< RESPONSE PROCESS:');
    console.log(JSON.stringify(procData, null, 2));

    const decPayload = decryptAES(kmBuffer, procData.encryptedData);
    console.log('\x1b[32m%s\x1b[0m', '<< RESPUESTA DESCIFRADA:', decPayload);

    console.log('\x1b[36m%s\x1b[0m', '--- DEMO FINALIZADA CON ÉXITO ---');
}

runDemo().then(() => {
    process.exit(0);
}).catch(err => {
    console.error('\n\x1b[31m%s\x1b[0m', '❌ ERROR:', err);
    process.exit(1);
});
