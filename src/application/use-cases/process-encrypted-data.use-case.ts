import { CRYPTO, CryptoCurve, REDIS_KEYS, TTL, Encoding, ERROR_MESSAGES, HttpStatus } from "../../config/constants";
import { ICryptoProvider } from "../../domain/interfaces/crypto-provider.interface";
import { ISessionRepository } from "../../domain/interfaces/session-repository.interface";
import { ProcessRequestDTO, ProcessResponseDTO } from "../dtos/process.dto";
import { v4 as uuidv4 } from 'uuid';

export class ProcessEncryptedData {
    constructor(
        private cryptoProvider: ICryptoProvider,
        private sessionRepository: ISessionRepository
    ) { }

    async execute(request: ProcessRequestDTO): Promise<ProcessResponseDTO> {
        const { deviceId, kid, publicKeyEphemeral, encryptedData } = request;

        // 1. Recovery (Parallelized Redis Calls)
        const [primarySecret, ephemeralPrivateKey] = await Promise.all([
            this.sessionRepository.getPrimarySecret(deviceId),
            this.sessionRepository.getEphemeralPrivateKey(kid)
        ]);

        if (!primarySecret || !ephemeralPrivateKey) {
            throw new Error(ERROR_MESSAGES.INVALID_SESSION);
        }

        /**
         * Parses a base64 encoded payload that contains IV + Tag + Ciphertext
         */
        const parseEncrypted = (base64: string) => {
            const buffer = Buffer.from(base64, Encoding.BASE64);
            const iv = buffer.subarray(0, CRYPTO.IV_BYTES).toString(Encoding.HEX);
            const tag = buffer.subarray(CRYPTO.IV_BYTES, CRYPTO.IV_BYTES + CRYPTO.TAG_BYTES).toString(Encoding.HEX);
            const payload = buffer.subarray(CRYPTO.IV_BYTES + CRYPTO.TAG_BYTES).toString(Encoding.HEX);
            return { iv, tag, payload };
        };

        const encodeEncrypted = (enc: { iv: string, tag: string, payload: string }) => {
            return Buffer.concat([
                Buffer.from(enc.iv, Encoding.HEX),
                Buffer.from(enc.tag, Encoding.HEX),
                Buffer.from(enc.payload, Encoding.HEX)
            ]).toString(Encoding.BASE64);
        };

        // 2. Decrypt Client Ephemeral Public Key (HEX) using primarySecret
        const clientEph = parseEncrypted(publicKeyEphemeral);
        let clientEphHex: string;
        try {
            clientEphHex = this.cryptoProvider.decryptAESGCM(
                primarySecret,
                clientEph.payload,
                clientEph.iv,
                clientEph.tag
            );
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.DECRYPTION_FAILED}: ${e.message}`);
        }

        // 3. Compute Ephemeral Shared Secret (SS_e)
        const ssE = this.cryptoProvider.computeSharedSecret(ephemeralPrivateKey, clientEphHex, CryptoCurve.X25519);

        // 4. Derive Message Key (K_m)
        const km = this.cryptoProvider.deriveMessageKey(primarySecret, ssE, deviceId);

        // 5. Decrypt Payload
        const data = parseEncrypted(encryptedData);
        let plaintext: string;
        try {
            plaintext = this.cryptoProvider.decryptAESGCM(
                km,
                data.payload,
                data.iv,
                data.tag
            );
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.DECRYPTION_FAILED}: ${e.message}`);
        }

        // --- PREPARACIÓN DE RESPUESTA Y NUEVA SESIÓN ---

        // 7. Process Business Logic
        const payloadObj = JSON.parse(plaintext);
        payloadObj.timestamp = new Date().toISOString();
        const responsePlaintext = JSON.stringify(payloadObj);

        // 8. Generate NEW Ephemeral Key Pair for NEXT message
        const nextKeyPair = this.cryptoProvider.generateKeyPair(CryptoCurve.X25519);
        const nextKid = uuidv4();
        const ttl = TTL.SESSION_SECONDS;

        // 6, 9, 10. Parallel Storage Block
        await Promise.all([
            this.sessionRepository.setKeyExpiry(REDIS_KEYS.EPHEMERAL_PREFIX + kid, TTL.EXPIRED_KEY_SECONDS),
            this.sessionRepository.storeEphemeralPrivateKey(nextKid, nextKeyPair.privateKey, ttl),
            this.sessionRepository.storeLastKidMapping(deviceId, nextKid, ttl)
        ]);

        // 11. Encrypt Response with Km
        const encRes = this.cryptoProvider.encryptAESGCM(km, responsePlaintext);
        const encryptedDataB64 = encodeEncrypted(encRes);

        // 12. Encrypt New Backend Ephemeral Public Key (HEX) with primarySecret
        const encNextEph = this.cryptoProvider.encryptAESGCM(primarySecret, nextKeyPair.publicKeyHex!);
        const nextEphB64 = encodeEncrypted(encNextEph);

        return {
            encryptedData: encryptedDataB64,
            publicKeyEphemeral: nextEphB64,
            kid: nextKid,
            duration: 100
        };
    }
}
