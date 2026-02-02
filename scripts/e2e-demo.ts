import pkg from 'elliptic';
const { ec: EC } = pkg;
import * as nodeCrypto from 'crypto';
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';

const ec = new EC('secp256k1');

/**
 * CLIENTE DE DEMOSTRACIÓN E2E - OPTIMIZADO CON BASE64
 * --------------------------------------------------
 * Formato del mensaje cifrado: Base64(IV + Tag + Payload)
 */

async function runDemo() {
    const baseUrl = 'https://handsheck-d0dshcd5bfh2g7bm.centralus-01.azurewebsites.net/api';
    const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
    const deviceId = uuidv5(uuidv4(), NAMESPACE); // Generar UUID v5 dinámico

    // Ayudantes Criptográficos
    const pemToHex = (pem: string) => {
        const key = nodeCrypto.createPublicKey(pem);
        const jwk = key.export({ format: 'jwk' });
        const x = Buffer.from(jwk.x!, 'base64url').toString('hex');
        const y = Buffer.from(jwk.y!, 'base64url').toString('hex');
        return '04' + x.padStart(64, '0') + y.padStart(64, '0');
    };

    const hexToPem = (publicKeyHex: string) => {
        const key = ec.keyFromPublic(publicKeyHex, 'hex');
        const pub = key.getPublic();
        const x = Buffer.from(pub.getX().toArray('be', 32)).toString('base64url');
        const y = Buffer.from(pub.getY().toArray('be', 32)).toString('base64url');
        const jwk = { kty: 'EC', crv: 'secp256k1', x, y };
        const keyObject = nodeCrypto.createPublicKey({ key: jwk as any, format: 'jwk' });
        return keyObject.export({ type: 'spki', format: 'pem' }) as string;
    };

    const encryptB64 = (keyHex: string, plaintext: string) => {
        const iv = nodeCrypto.randomBytes(12);
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
        let payload = cipher.update(plaintext, 'utf8');
        payload = Buffer.concat([payload, cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, payload]).toString('base64');
    };

    const decryptB64 = (keyHex: string, base64: string) => {
        const buffer = Buffer.from(base64, 'base64');
        const iv = buffer.subarray(0, 12);
        const tag = buffer.subarray(12, 28);
        const payload = buffer.subarray(28);
        const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
        decipher.setAuthTag(tag);
        let decrypted = decipher.update(payload, undefined, 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    };

    console.log('\x1b[36m%s\x1b[0m', '--- [1] INICIANDO HANDSHAKE ---');

    const clientPrimary = ec.genKeyPair();
    const hsRequest = { deviceId, publicKeyPrimary: hexToPem(clientPrimary.getPublic(true, 'hex')) };

    const hsResponse = await fetch(`${baseUrl}/httpTriggerHandsheck`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hsRequest)
    });

    const hsData = await hsResponse.json();
    const { publicKeyPrimary: backendPubPEM, publicKeyEphemeral: backendEphPEM, kid } = hsData;
    console.log('✔ Handshake OK. KID:', kid);

    // --- [2] SEGUURIDAD: SS_p ---
    const ssP = clientPrimary.derive(ec.keyFromPublic(pemToHex(backendPubPEM), 'hex').getPublic()).toString(16).padStart(64, '0');
    console.log('✔ SS_p [Base64]:', Buffer.from(ssP, 'hex').toString('base64'));

    // --- [3] LLAVE EFÍMERA CIFRADA CON SS_p ---
    const clientEphemeral = ec.genKeyPair();
    const encClientEph = encryptB64(ssP, hexToPem(clientEphemeral.getPublic(true, 'hex')));

    // --- [4] DERIVACIÓN Km ---
    const ssE = clientEphemeral.derive(ec.keyFromPublic(pemToHex(backendEphPEM), 'hex').getPublic()).toString(16).padStart(64, '0');
    const km = nodeCrypto.createHash('sha256').update(Buffer.from(ssP, 'hex')).update(Buffer.from(ssE, 'hex')).digest('hex');
    console.log('✔ Km [Base64]:', Buffer.from(km, 'hex').toString('base64'));

    // --- [5] ENVIANDO PETICIÓN PROCESS ---
    console.log('\n\x1b[36m%s\x1b[0m', '--- [3] ENVIANDO PETICIÓN OPTIMIZADA (PROCESS) ---');
    const message = JSON.stringify({ action: "optimized_test", data: "Base64 Segment Concatenation", ts: Date.now() });
    const encData = encryptB64(km, message);

    const processRequest = {
        deviceId,
        kid,
        publicKeyEphemeral: encClientEph,
        encryptedData: encData
    };

    console.log('\x1b[33m%s\x1b[0m', '>> REQUEST PROCESS (Optimized):');
    console.log(JSON.stringify(processRequest, null, 2));

    const procResponse = await fetch(`${baseUrl}/httpTriggerProcess`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(processRequest)
    });

    const procData = await procResponse.json();
    console.log('\x1b[32m%s\x1b[0m', '<< RESPONSE PROCESS:');
    console.log(JSON.stringify(procData, null, 2));

    // --- [6] DESCIFRADO ---
    console.log('\n\x1b[36m%s\x1b[0m', '--- [4] DESCIFRANDO RESPUESTA ---');
    const decryptedBody = decryptB64(km, procData.encryptedData);
    console.log('\x1b[32m%s\x1b[0m', '✔ Datos descifrados OK:');
    console.log(JSON.stringify(JSON.parse(decryptedBody), null, 2));

    console.log('\x1b[36m%s\x1b[0m', '--- DEMO FINALIZADA CON ÉXITO ---');
}

runDemo().catch(err => console.error('\n\x1b[31m%s\x1b[0m', '❌ ERROR:', err));
