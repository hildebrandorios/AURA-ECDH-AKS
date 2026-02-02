import pkg from 'elliptic';
const { ec: EC } = pkg;
import * as nodeCrypto from 'crypto';
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';
import { performance } from 'perf_hooks';

console.log('>>> PERFORMANCE TEST SCRIPT LOADED (LOGIC V5 - ADVANCED METRICS)');

const ec = new EC('secp256k1');
const FETCH_TIMEOUT = 30000; // Aumentado a 30s para evitar AbortErrors en picos de carga
const LOG_FILE = path.join(process.cwd(), 'performance_errors.log');

if (fs.existsSync(LOG_FILE)) fs.unlinkSync(LOG_FILE);

interface MetricBlock {
    latencies: number[];
    success: number;
    fail: number;
}

interface CryptoMetrics {
    keyGen: number[];
    encryption: number[];
    decryption: number[];
}

interface ResourceMetrics {
    cpuStart: NodeJS.CpuUsage;
    memPeak: number;
}

interface Metrics {
    startTime: number;
    endTime: number;
    handshake: MetricBlock;
    process: MetricBlock;
    crypto: CryptoMetrics;
    resource: ResourceMetrics;
}

const metrics: Metrics = {
    startTime: 0,
    endTime: 0,
    handshake: { latencies: [], success: 0, fail: 0 },
    process: { latencies: [], success: 0, fail: 0 },
    crypto: { keyGen: [], encryption: [], decryption: [] },
    resource: {
        cpuStart: process.cpuUsage(),
        memPeak: 0
    }
};

function trackMemory() {
    const mem = process.memoryUsage().rss;
    if (mem > metrics.resource.memPeak) metrics.resource.memPeak = mem;
}

function logError(type: string, userId: string, message: string, detail?: any, error?: Error | any) {
    const timestamp = new Date().toISOString();
    let logEntry = `--------------------------------------------------------------------------------\n`;
    logEntry += `[${timestamp}] [${type}] [User: ${userId}]\n`;
    logEntry += `MESSAGE: ${message}\n`;

    if (detail) {
        logEntry += `CONTEXT/RESPONSE BODY: ${typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2)}\n`;
    }

    if (error) {
        if (error.stack) {
            logEntry += `STACK TRACE:\n${error.stack}\n`;
        } else if (typeof error === 'object') {
            logEntry += `ERROR OBJ: ${JSON.stringify(error, null, 2)}\n`;
        }
    }

    logEntry += `--------------------------------------------------------------------------------\n\n`;
    fs.appendFileSync(LOG_FILE, logEntry);
}

const pemToHex = (pem: string) => {
    const key = nodeCrypto.createPublicKey(pem);
    const jwk = key.export({ format: 'jwk' });
    const x = Buffer.from(jwk.x!, 'base64url').toString('hex');
    const y = Buffer.from(jwk.y!, 'base64url').toString('hex');
    return '04' + x.padStart(64, '0') + y.padStart(64, '0');
};

const hexToPem = (publicKeyHex: string) => {
    const start = performance.now();
    const key = ec.keyFromPublic(publicKeyHex, 'hex');
    const pub = key.getPublic();
    const x = Buffer.from(pub.getX().toArray('be', 32)).toString('base64url');
    const y = Buffer.from(pub.getY().toArray('be', 32)).toString('base64url');
    const jwk = { kty: 'EC', crv: 'secp256k1', x, y };
    const keyObject = nodeCrypto.createPublicKey({ key: jwk as any, format: 'jwk' });
    const pem = keyObject.export({ type: 'spki', format: 'pem' }) as string;
    // No trackeamos hexToPem por separado, se incluye en el flujo
    return pem;
};

const encryptB64 = (keyHex: string, plaintext: string) => {
    const start = performance.now();
    const iv = nodeCrypto.randomBytes(12);
    const cipher = nodeCrypto.createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
    let payload = cipher.update(plaintext, 'utf8');
    payload = Buffer.concat([payload, cipher.final()]);
    const tag = cipher.getAuthTag();
    const result = Buffer.concat([iv, tag, payload]).toString('base64');
    metrics.crypto.encryption.push(performance.now() - start);
    return result;
};

const decryptB64 = (keyHex: string, base64: string) => {
    const start = performance.now();
    const buffer = Buffer.from(base64, 'base64');
    const iv = buffer.subarray(0, 12);
    const tag = buffer.subarray(12, 28);
    const payload = buffer.subarray(28);
    const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(payload, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    metrics.crypto.decryption.push(performance.now() - start);
    return decrypted;
};

async function executeProcessRequest(baseUrl: string, deviceId: string, kid: string, ssP: string, backendEphPEM: string) {
    const start = Date.now();
    try {
        const startKG = performance.now();
        const clientEphemeral = ec.genKeyPair();
        metrics.crypto.keyGen.push(performance.now() - startKG);

        const encClientEph = encryptB64(ssP, hexToPem(clientEphemeral.getPublic(true, 'hex')));

        const ssE = clientEphemeral.derive(ec.keyFromPublic(pemToHex(backendEphPEM), 'hex').getPublic()).toString(16).padStart(64, '0');
        const km = nodeCrypto.createHash('sha256').update(Buffer.from(ssP, 'hex')).update(Buffer.from(ssE, 'hex')).digest('hex');

        const message = JSON.stringify({ action: "perf_test", ts: Date.now() });
        const encData = encryptB64(km, message);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

        const response = await fetch(`${baseUrl}/httpTriggerProcess`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId, kid, publicKeyEphemeral: encClientEph, encryptedData: encData }),
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorBody = await response.text();
            throw { message: `Server error ${response.status}`, body: errorBody };
        }

        const data = await response.json();

        const nextBackendEphPEM = decryptB64(ssP, data.publicKeyEphemeral);

        metrics.process.latencies.push(Date.now() - start);
        metrics.process.success++;

        trackMemory();

        return {
            nextKid: data.kid,
            nextBackendEphPEM: nextBackendEphPEM
        };
    } catch (error: any) {
        metrics.process.fail++;
        logError('PROCESS', deviceId, error.message || 'Unknown Error', error.body || { kid }, error);
        return null;
    }
}

async function runVirtualUser(userId: number, requestsPerUserTotal: number, totalDurationSeconds: number, baseUrl: string) {
    const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
    const deviceId = uuidv5(uuidv4(), NAMESPACE);

    const handshakesCount = Math.floor(Math.random() * 3) + 1;
    const reqsPerHS = Math.floor(requestsPerUserTotal / handshakesCount);
    const delay = (totalDurationSeconds * 1000) / requestsPerUserTotal;

    for (let h = 0; h < handshakesCount; h++) {
        try {
            const startHS = Date.now();

            const startKG = performance.now();
            const clientPrimary = ec.genKeyPair();
            metrics.crypto.keyGen.push(performance.now() - startKG);

            const hsRequest = { deviceId, publicKeyPrimary: hexToPem(clientPrimary.getPublic(true, 'hex')) };

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
            const hsResponse = await fetch(`${baseUrl}/httpTriggerHandsheck`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(hsRequest),
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (!hsResponse.ok) {
                const body = await hsResponse.text();
                throw { message: `Handshake Fail ${hsResponse.status}`, body };
            }
            const hsData = await hsResponse.json();

            metrics.handshake.latencies.push(Date.now() - startHS);
            metrics.handshake.success++;

            const ssP = clientPrimary.derive(ec.keyFromPublic(pemToHex(hsData.publicKeyPrimary), 'hex').getPublic()).toString(16).padStart(64, '0');

            let currentKid = hsData.kid;
            let currentBackendEphPEM = hsData.publicKeyEphemeral;
            const remaining = (h === handshakesCount - 1) ? requestsPerUserTotal - (h * reqsPerHS) : reqsPerHS;

            const parallelCount = Math.floor(remaining / 2);
            const sequentialCount = remaining - parallelCount;

            const parallelPool = Array.from({ length: parallelCount }).map(async () => {
                await new Promise(r => setTimeout(r, Math.random() * delay));
                return executeProcessRequest(baseUrl, deviceId, currentKid, ssP, currentBackendEphPEM);
            });

            const parallelResults = await Promise.all(parallelPool);
            const lastSuccess = parallelResults.reverse().find(r => r !== null);
            if (lastSuccess) {
                currentKid = lastSuccess.nextKid;
                currentBackendEphPEM = lastSuccess.nextBackendEphPEM;
            }

            for (let i = 0; i < sequentialCount; i++) {
                await new Promise(r => setTimeout(r, delay));
                const result = await executeProcessRequest(baseUrl, deviceId, currentKid, ssP, currentBackendEphPEM);
                if (result) {
                    currentKid = result.nextKid;
                    currentBackendEphPEM = result.nextBackendEphPEM;
                } else {
                    break;
                }
            }

            trackMemory();

        } catch (error: any) {
            metrics.handshake.fail++;
            logError('HANDSHAKE_FLOW', deviceId, error.message || 'Unknown Error', error.body || { h }, error);
        }
    }
}

async function runTest() {
    const args = process.argv.slice(2);
    const USERS = parseInt(args[args.indexOf('--users') + 1]) || 10;
    const TOTAL_REQUESTS = parseInt(args[args.indexOf('--requests') + 1]) || 100;
    const DURATION_SECONDS = parseInt(args[args.indexOf('--seconds') + 1]) || 5;
    const baseUrl = 'https://handsheck-d0dshcd5bfh2g7bm.centralus-01.azurewebsites.net/api';

    console.log('\x1b[36m%s\x1b[0m', '--- INICIANDO PRUEBA DE CARGA (LOGIC V5 - AVANCED) ---');
    console.log(`Configuración: ${USERS} usuarios concurrentes, ${TOTAL_REQUESTS} peticiones totales`);

    const requestsPerUser = Math.floor(TOTAL_REQUESTS / USERS);
    metrics.startTime = Date.now();

    const PromiseUsers = Array.from({ length: USERS }).map((_, i) => runVirtualUser(i, requestsPerUser, DURATION_SECONDS, baseUrl));

    await Promise.all(PromiseUsers);

    metrics.endTime = Date.now();
    printResults();
}

function printBlockMetrics(name: string, block: MetricBlock) {
    const sorted = block.latencies.sort((a, b) => a - b);
    const min = sorted.length ? sorted[0] : 0;
    const max = sorted.length ? sorted[sorted.length - 1] : 0;
    const avg = sorted.length ? (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(2) : 0;

    console.log(`\n\x1b[33m[${name.toUpperCase()}]\x1b[0m`);
    console.log(`  Exitosas: ${block.success} | Fallidas: ${block.fail}`);
    console.log(`  Latencia: Min: ${min}ms | Avg: ${avg}ms | Max: ${max}ms`);
}

function printCryptoMetrics(name: string, lats: number[]) {
    const sorted = lats.sort((a, b) => a - b);
    const min = sorted.length ? sorted[0].toFixed(3) : '0';
    const max = sorted.length ? sorted[sorted.length - 1].toFixed(3) : '0';
    const avg = sorted.length ? (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(3) : '0';
    console.log(`  ${name.padEnd(8)}: Min: ${min}ms | Avg: ${avg}ms | Max: ${max}ms`);
}

function printResults() {
    const duration = (metrics.endTime - metrics.startTime) / 1000;
    const cpuEnd = process.cpuUsage(metrics.resource.cpuStart);
    const totalCpuTime = (cpuEnd.user + cpuEnd.system) / 1000; // ms

    console.log('\n\x1b[32m%s\x1b[0m', '--- RESULTADOS DE RENDIMIENTO ---');
    console.log(`Tiempo Total: ${duration.toFixed(2)}s`);

    printBlockMetrics('Handshake (Network)', metrics.handshake);
    printBlockMetrics('Process (Network)', metrics.process);

    console.log(`\n\x1b[35m[CLIENT CRYPTO OVERHEAD]\x1b[0m`);
    printCryptoMetrics('KeyGen', metrics.crypto.keyGen);
    printCryptoMetrics('Encrypt', metrics.crypto.encryption);
    printCryptoMetrics('Decrypt', metrics.crypto.decryption);

    console.log(`\n\x1b[34m[RESOURCE CONSUMPTION]\x1b[0m`);
    console.log(`  CPU Usage: ${(totalCpuTime / (duration * 1000) * 100).toFixed(2)}% (User: ${cpuEnd.user / 1000}ms, Sys: ${cpuEnd.system / 1000}ms)`);
    console.log(`  Memory Peak (RSS): ${(metrics.resource.memPeak / 1024 / 1024).toFixed(2)} MB`);

    const totalSuccess = metrics.handshake.success + metrics.process.success;
    const totalFail = metrics.handshake.fail + metrics.process.fail;

    console.log(`\n\x1b[36m[RESUMEN GENERAL]\x1b[0m`);
    console.log(`  Total OK: ${totalSuccess} | Total FALLO: ${totalFail}`);
    console.log(`  Throughput Global: ${(totalSuccess / duration).toFixed(2)} req/s`);

    if (totalFail > 0) {
        console.log(`\n\x1b[31m%s\x1b[0m`, `DETALLE DE ERRORES GUARDADO EN: performance_errors.log`);
    }
}

runTest().catch(err => console.error('Fatal Error:', err));
