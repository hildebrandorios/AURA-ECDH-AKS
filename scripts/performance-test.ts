import pkg from 'elliptic';
const { ec: EC } = pkg;
import * as nodeCrypto from 'crypto';
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';
import { performance } from 'perf_hooks';
import { Encoding, CryptoCurve, CRYPTO } from '../src/config/constants';

/**
 * PERFORMANCE TEST SCRIPT - SEGURIDAD V9 (REFACTORIZADO)
 * -----------------------------------------------------
 */

const ec = new EC(CryptoCurve.SECP256K1);
const FETCH_TIMEOUT = 30000;
const LOG_FILE = path.join(process.cwd(), 'performance_errors.log');

if (fs.existsSync(LOG_FILE)) fs.unlinkSync(LOG_FILE);

const SERVER_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJVond8ty13vMS9XyEVu
/LQ8okK3OzH/FHzQfsOI1x+bKFyL+uXSg/sTTboBbohQaqvn/podnXzzlwG5htAS
9nwhYB/DUf7JJfmlgUw+99etXbgv52DUR4GEEoId092giNWIyLPPD3hkaelAwGUp
T4QT0aBGa2bOeoSNydHXK12SETdLYaI5nbQzvwHrHo4EkUlkAm4MivLD5gjCGO8s
qEkFMOl/6srYw24HPVTLu5ltBe+Dyk8oeiDMpFoZWlo0I/AyRJAdQCMvD2MDd4s4
ikJLwI37pQeZjEqWnC3oh3xv7hysZ88V4URZmpK8BhLFMbt0TEpwwEWpCIUiNF/c
EQIDAQAB
-----END PUBLIC KEY-----`;

interface MetricBlock {
    total: number[];
    network: number[];
    local: number[];
    success: number;
    fail: number;
}

interface Metrics {
    startTime: number;
    endTime: number;
    handshake: MetricBlock;
    process: MetricBlock;
    crypto: {
        rsaEnc: number[];
        rsaDec: number[];
        aesEnc: number[];
        aesDec: number[];
        hkdf: number[];
        s256Gen: number[];
        s256Derive: number[];
        x255Gen: number[];
        x255Derive: number[];
    };
}

const metrics: Metrics = {
    startTime: 0,
    endTime: 0,
    handshake: { total: [], network: [], local: [], success: 0, fail: 0 },
    process: { total: [], network: [], local: [], success: 0, fail: 0 },
    crypto: {
        rsaEnc: [],
        rsaDec: [],
        aesEnc: [],
        aesDec: [],
        hkdf: [],
        s256Gen: [],
        s256Derive: [],
        x255Gen: [],
        x255Derive: []
    }
};

function logError(msg: string) {
    fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${msg}\n`);
}

const encryptRSAPublic = (publicKey: string, data: string) => {
    const start = performance.now();
    const res = nodeCrypto.publicEncrypt({
        key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: CRYPTO.HASH_ALGORITHM
    }, Buffer.from(data, Encoding.UTF8)).toString(Encoding.BASE64);
    metrics.crypto.rsaEnc.push(performance.now() - start);
    return res;
};

const decryptRSAPublic = (publicKey: string, base64: string) => {
    const start = performance.now();
    const res = nodeCrypto.publicDecrypt({
        key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PADDING
    }, Buffer.from(base64, Encoding.BASE64)).toString(Encoding.UTF8);
    metrics.crypto.rsaDec.push(performance.now() - start);
    return res;
};

const encryptAES = (key: Buffer, plaintext: string) => {
    const start = performance.now();
    const iv = nodeCrypto.randomBytes(CRYPTO.IV_BYTES);
    const cipher = nodeCrypto.createCipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
    let payload = cipher.update(plaintext, Encoding.UTF8);
    payload = Buffer.concat([payload, cipher.final()]);
    const tag = cipher.getAuthTag();
    const res = Buffer.concat([iv, tag, payload]).toString(Encoding.BASE64);
    metrics.crypto.aesEnc.push(performance.now() - start);
    return res;
};

const decryptAES = (key: Buffer, base64: string) => {
    const start = performance.now();
    const buffer = Buffer.from(base64, Encoding.BASE64);
    const iv = buffer.subarray(0, CRYPTO.IV_BYTES);
    const tag = buffer.subarray(CRYPTO.IV_BYTES, CRYPTO.IV_BYTES + CRYPTO.TAG_BYTES);
    const payload = buffer.subarray(CRYPTO.IV_BYTES + CRYPTO.TAG_BYTES);
    const decipher = nodeCrypto.createDecipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(payload, undefined, Encoding.UTF8);
    decrypted += decipher.final(Encoding.UTF8);
    metrics.crypto.aesDec.push(performance.now() - start);
    return decrypted;
};

async function executeProcessRequest(baseUrl: string, deviceId: string, kid: string, primarySecret: Buffer, backendEphHex: string) {
    const totalStart = performance.now();
    let netDuration = 0;

    try {
        const startEphGen = performance.now();
        const clientEphPair = nodeCrypto.generateKeyPairSync(CryptoCurve.X25519);
        const clientEphHex = Buffer.from((clientEphPair.publicKey.export({ format: 'jwk' }) as any).x, Encoding.BASE64URL).toString(Encoding.HEX);
        metrics.crypto.x255Gen.push(performance.now() - startEphGen);

        const encClientEph = encryptAES(primarySecret, clientEphHex);

        const plaintext = JSON.stringify({ action: "test", data: "perf-check", nonce: uuidv4() });
        const startSSE = performance.now();

        // El secreto compartido se calcula con la privada local y la pública remota (backend)
        const backendEphPubKey = nodeCrypto.createPublicKey({
            key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(backendEphHex, Encoding.HEX).toString(Encoding.BASE64URL) },
            format: 'jwk'
        });

        const ssE = nodeCrypto.diffieHellman({
            privateKey: clientEphPair.privateKey,
            publicKey: backendEphPubKey
        });
        metrics.crypto.x255Derive.push(performance.now() - startSSE);

        const startHKDF = performance.now();
        const km = nodeCrypto.hkdfSync(CRYPTO.HASH_ALGORITHM, Buffer.concat([primarySecret, ssE]), Buffer.from(deviceId), CRYPTO.HKDF_INFO_MESSAGE, 32);
        const kmBuffer = Buffer.from(km);
        metrics.crypto.hkdf.push(performance.now() - startHKDF);

        const encData = encryptAES(kmBuffer, plaintext);

        const netStart = performance.now();
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
        const response = await fetch(`${baseUrl}/httpTriggerProcess`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId, kid, publicKeyEphemeral: encClientEph, encryptedData: encData }),
            signal: ctrl.signal
        });

        if (!response.ok) {
            netDuration = performance.now() - netStart;
            metrics.process.network.push(netDuration);
            const errBody = await response.text();
            throw new Error(`Process error ${response.status}: ${errBody}`);
        }

        const data = await response.json();
        netDuration = performance.now() - netStart;
        metrics.process.network.push(netDuration);
        clearTimeout(timeout);

        const decryptedPayload = decryptAES(kmBuffer, data.encryptedData);
        const nextEphHex = decryptAES(primarySecret, data.publicKeyEphemeral);

        const totalExec = performance.now() - totalStart;
        metrics.process.total.push(totalExec);
        metrics.process.local.push(totalExec - netDuration);
        metrics.process.success++;
        return { nextKid: data.kid, nextEphHex };
    } catch (error: any) {
        logError(`Process Error: ${error.message}`);
        metrics.process.fail++;
        return null;
    }
}

async function executeHandshake(baseUrl: string, deviceId: string) {
    const totalStart = performance.now();
    let netDuration = 0;

    try {
        const startS256Gen = performance.now();
        const clientPrimary = ec.genKeyPair();
        const pubPrimaryHex = clientPrimary.getPublic(true, Encoding.HEX);
        metrics.crypto.s256Gen.push(performance.now() - startS256Gen);

        const hsRequest = {
            deviceId: deviceId,
            publicKeyPrimary: encryptRSAPublic(SERVER_RSA_PUBLIC_KEY, pubPrimaryHex)
        };

        const netStart = performance.now();
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
        const response = await fetch(`${baseUrl}/httpTriggerHandsheck`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(hsRequest),
            signal: ctrl.signal
        });

        if (!response.ok) {
            netDuration = performance.now() - netStart;
            metrics.handshake.network.push(netDuration);
            const errBody = await response.text();
            throw new Error(`Handshake Fail ${response.status}: ${errBody}`);
        }

        const hsData = await response.json();
        netDuration = performance.now() - netStart;
        metrics.handshake.network.push(netDuration);
        clearTimeout(timeout);

        const backendPubHex = decryptRSAPublic(SERVER_RSA_PUBLIC_KEY, hsData.publicKeyPrimary);
        const backendEphHex = decryptRSAPublic(SERVER_RSA_PUBLIC_KEY, hsData.publicKeyEphemeral);

        const startS256SS = performance.now();
        const ssP = Buffer.from(clientPrimary.derive(ec.keyFromPublic(backendPubHex, Encoding.HEX).getPublic()).toArray('be', 32));
        metrics.crypto.s256Derive.push(performance.now() - startS256SS);

        const totalExec = performance.now() - totalStart;
        metrics.handshake.total.push(totalExec);
        metrics.handshake.local.push(totalExec - netDuration);
        metrics.handshake.success++;

        return { kid: hsData.kid, ssP, backendEphHex };
    } catch (error: any) {
        logError(`Handshake Error: ${error.message}`);
        metrics.handshake.fail++;
        return null;
    }
}

async function runTest() {
    const args = process.argv.slice(2);
    const usersCount = parseInt(args[args.indexOf('--users') + 1]) || 1;
    const requestsPerUser = parseInt(args[args.indexOf('--requests') + 1]) || 5;
    const baseUrl = 'http://localhost:3000/api';

    console.log(`\x1b[1m%s\x1b[0m`, `--- INICIANDO PRUEBA RENDIMIENTO V9 (REFACTORIZADO) ---`);
    console.log(`Configuración: Usuarios=${usersCount}, Peticiones/Usuario=${requestsPerUser}`);
    console.log(`Endpoint: ${baseUrl}\n`);

    metrics.startTime = performance.now();

    const userTasks = Array.from({ length: usersCount }).map(async (_, i) => {
        const deviceId = uuidv5(`user-${i}`, '6ba7b810-9dad-11d1-80b4-00c04fd430c8');

        const hsResult = await executeHandshake(baseUrl, deviceId);
        if (!hsResult) return;

        let { kid, ssP, backendEphHex } = hsResult;

        for (let j = 0; j < requestsPerUser; j++) {
            const procResult = await executeProcessRequest(baseUrl, deviceId, kid, ssP, backendEphHex);
            if (!procResult) break;
            kid = procResult.nextKid;
            backendEphHex = procResult.nextEphHex;
        }
    });

    await Promise.all(userTasks);
    metrics.endTime = performance.now();

    printResults();
}

function printResults() {
    const duration = (metrics.endTime - metrics.startTime) / 1000;

    const getStats = (arr: number[]) => {
        if (arr.length === 0) return { min: "0.000", avg: "0.000", max: "0.000" };
        const min = Math.min(...arr).toFixed(3);
        const max = Math.max(...arr).toFixed(3);
        const avg = (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(3);
        return { min, avg, max };
    };

    const fmt = (s: { min: string, avg: string, max: string }) =>
        `Min: ${s.min.padStart(8)} | Avg: ${s.avg.padStart(8)} | Max: ${s.max.padStart(8)}`;

    console.log(`\n\x1b[1m\x1b[36m%s\x1b[0m`, `--- RESULTADOS FINALES ---`);
    console.log(`Tiempo Total Ejecución: ${duration.toFixed(2)}s`);

    console.log(`\n\x1b[33m%s\x1b[0m`, `>> FLUJO DE RED Y PROCESAMIENTO LOCAL (Ms):`);
    console.log(`[Handshake]`);
    console.log(`  Enviadas: ${metrics.handshake.success + metrics.handshake.fail} | Éxito: ${metrics.handshake.success} | Fallo: ${metrics.handshake.fail}`);
    console.log(`  Red   | ${fmt(getStats(metrics.handshake.network))}`);
    console.log(`  Local | ${fmt(getStats(metrics.handshake.local))}`);
    console.log(`  TOTAL | ${fmt(getStats(metrics.handshake.total))}`);

    console.log(`[Process]`);
    console.log(`  Enviadas: ${metrics.process.success + metrics.process.fail} | Éxito: ${metrics.process.success} | Fallo: ${metrics.process.fail}`);
    console.log(`  Red   | ${fmt(getStats(metrics.process.network))}`);
    console.log(`  Local | ${fmt(getStats(metrics.process.local))}`);
    console.log(`  TOTAL | ${fmt(getStats(metrics.process.total))}`);

    console.log(`\n\x1b[35m%s\x1b[0m`, `>> DESGLOSE CRIPTOGRÁFICO DETALLADO (Ms):`);

    console.log(`RSA Encrypt     | ${fmt(getStats(metrics.crypto.rsaEnc))}`);
    console.log(`RSA Decrypt     | ${fmt(getStats(metrics.crypto.rsaDec))}`);
    console.log(`AES-GCM Encrypt | ${fmt(getStats(metrics.crypto.aesEnc))}`);
    console.log(`AES-GCM Decrypt | ${fmt(getStats(metrics.crypto.aesDec))}`);
    console.log(`HKDF SHA-256    | ${fmt(getStats(metrics.crypto.hkdf))}`);
    console.log(`SECP256K1 Gen   | ${fmt(getStats(metrics.crypto.s256Gen))}`);
    console.log(`SECP256K1 SS    | ${fmt(getStats(metrics.crypto.s256Derive))}`);
    console.log(`X25519 Gen      | ${fmt(getStats(metrics.crypto.x255Gen))}`);
    console.log(`X25519 SS       | ${fmt(getStats(metrics.crypto.x255Derive))}`);

    console.log(`\n\x1b[1m\x1b[32m%s\x1b[0m`, `--- PRUEBA FINALIZADA ---`);
}

runTest().then(() => {
    process.exit(0);
}).catch(err => {
    console.error(err);
    process.exit(1);
});
