import { CRYPTO, CryptoCurve, REDIS_KEYS, TTL, Encoding } from "../../config/constants";
import { ICryptoProvider } from "../../domain/interfaces/crypto-provider.interface";
import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { ISessionRepository } from "../../domain/interfaces/session-repository.interface";
import { HandshakeRequestDTO, HandshakeResponseDTO } from "../dtos/handshake.dto";
import { v4 as uuidv4 } from 'uuid';
import * as nodeCrypto from 'crypto';

export class PerformHandshake {
    constructor(
        private readonly cryptoProvider: ICryptoProvider,
        private readonly identityService: IIdentityService,
        private readonly sessionRepository: ISessionRepository
    ) { }

    public async execute(request: HandshakeRequestDTO): Promise<HandshakeResponseDTO> {
        // 0. RSA Decrypt Fields
        const deviceId = request.deviceId;
        const publicKeyPrimary = await this.identityService.decryptRSA(request.publicKeyPrimary);

        // 1. Get Entropy from Identity Service (Cached)
        const entropy = this.identityService.getEntropy();

        // 2. Derive Primary Key (Identity-linked + Nonce)
        const primaryNonce = nodeCrypto.randomBytes(CRYPTO.NONCE_BYTES);
        const backendPrimaryPair = this.cryptoProvider.deriveKeyPairFromEntropy(entropy, primaryNonce);

        // 3. Generate Ephemeral KeyPair (X25519)
        const backendEphemeralPair = this.cryptoProvider.generateKeyPair(CryptoCurve.X25519);

        // 4. Compute Shared Secret (SECP256K1 for Primary)
        const sharedSecretPrimary = this.cryptoProvider.computeSharedSecret(
            backendPrimaryPair.privateKey,
            publicKeyPrimary,
            CryptoCurve.SECP256K1
        );

        const kid = uuidv4();

        // 5. Manage Session Uniqueness & Storage
        const oldKid = await this.sessionRepository.getLastKid(deviceId);

        if (oldKid) {
            await this.sessionRepository.setKeyExpiry(REDIS_KEYS.EPHEMERAL_PREFIX + oldKid, TTL.EXPIRED_KEY_SECONDS);
        }

        const ttl = TTL.SESSION_SECONDS;
        await Promise.all([
            this.sessionRepository.storePrimarySecret(deviceId, sharedSecretPrimary, ttl),
            this.sessionRepository.storeEphemeralPrivateKey(kid, backendEphemeralPair.privateKey, ttl),
            this.sessionRepository.storeLastKidMapping(deviceId, kid, ttl)
        ]);

        const pubPHex = backendPrimaryPair.publicKeyHex!;
        const pubEHex = backendEphemeralPair.publicKeyHex!;

        return {
            publicKeyPrimary: this.identityService.encryptRSAPrivate(pubPHex),
            publicKeyEphemeral: this.identityService.encryptRSAPrivate(pubEHex),
            kid,
            duration: 100
        };
    }
}
