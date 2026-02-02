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

        // 1. Recovery
        const primarySecret = await this.sessionRepository.getPrimarySecret(deviceId);
        const ephemeralPrivateKey = await this.sessionRepository.getEphemeralPrivateKey(kid);

        if (!primarySecret || !ephemeralPrivateKey) {
            throw new Error("401: Invalid session or device");
        }

        // Helper to parse Base64(IV + Tag + Payload)
        const parseEncrypted = (base64: string) => {
            const buffer = Buffer.from(base64, 'base64');
            const iv = buffer.subarray(0, 12).toString('hex');
            const tag = buffer.subarray(12, 28).toString('hex');
            const payload = buffer.subarray(28).toString('hex');
            return { iv, tag, payload };
        };

        // Helper to encode (IV + Tag + Payload) to Base64
        const encodeEncrypted = (enc: { iv: string, tag: string, payload: string }) => {
            return Buffer.concat([
                Buffer.from(enc.iv, 'hex'),
                Buffer.from(enc.tag, 'hex'),
                Buffer.from(enc.payload, 'hex')
            ]).toString('base64');
        };

        // 2. Decrypt Client Ephemeral Public Key (PEM) using primarySecret
        const clientEph = parseEncrypted(publicKeyEphemeral);
        let clientEphPEM: string;
        try {
            clientEphPEM = this.cryptoProvider.decryptAESGCM(
                primarySecret,
                clientEph.payload,
                clientEph.iv,
                clientEph.tag
            );
        } catch (e: any) {
            throw new Error(`Failed to decrypt publicKeyEphemeral: ${e.message}`);
        }

        // 3. Compute Ephemeral Shared Secret (SS_e)
        const ssE = this.cryptoProvider.computeSharedSecret(ephemeralPrivateKey, clientEphPEM);

        // 4. Derive Message Key (K_m) = SHA256(SS_p + SS_e)
        const km = this.cryptoProvider.deriveMessageKey(primarySecret, ssE);

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
            throw new Error(`Failed to decrypt payload: ${e.message}`);
        }

        // 6. Update TTL for used KID to 5 minutes (300 seconds)
        await this.sessionRepository.setKeyExpiry(`handshake:eph:${kid}`, 300);

        // 7. Process Business Logic
        const payloadObj = JSON.parse(plaintext);
        payloadObj.timestamp = new Date().toISOString();
        const responsePlaintext = JSON.stringify(payloadObj);

        // 8. Generate NEW Ephemeral Key Pair for NEXT message
        const nextKeyPair = this.cryptoProvider.generateKeyPair();
        const nextKid = uuidv4();

        // 9. Store NEW Ephemeral Private Key (TTL 24h)
        const TTL_24H = 24 * 60 * 60;
        await this.sessionRepository.storeEphemeralPrivateKey(nextKid, nextKeyPair.privateKey, TTL_24H);

        // 10. Update last KID mapping
        await this.sessionRepository.storeLastKidMapping(deviceId, nextKid, TTL_24H);

        // 11. Encrypt Response with Km
        const encRes = this.cryptoProvider.encryptAESGCM(km, responsePlaintext);
        const encryptedDataB64 = encodeEncrypted(encRes);

        // 12. Encrypt New Backend Ephemeral Public Key with primarySecret
        const nextEphPEM = this.cryptoProvider.exportPublicKeyToPEM(nextKeyPair.publicKey);
        const encNextEph = this.cryptoProvider.encryptAESGCM(primarySecret, nextEphPEM);
        const nextEphB64 = encodeEncrypted(encNextEph);

        return {
            encryptedData: encryptedDataB64,
            publicKeyEphemeral: nextEphB64,
            kid: nextKid
        };
    }
}
