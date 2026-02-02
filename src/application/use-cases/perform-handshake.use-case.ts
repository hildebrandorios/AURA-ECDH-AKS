import { REDIS_KEYS } from "../../config/constants";
import { ICryptoProvider } from "../../domain/interfaces/crypto-provider.interface";
import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { ISessionRepository } from "../../domain/interfaces/session-repository.interface";
import { HandshakeRequestDTO, HandshakeResponseDTO } from "../dtos/handshake.dto";
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

export class PerformHandshake {
    constructor(
        private readonly cryptoProvider: ICryptoProvider,
        private readonly identityService: IIdentityService,
        private readonly sessionRepository: ISessionRepository
    ) { }

    public async execute(request: HandshakeRequestDTO): Promise<HandshakeResponseDTO> {
        const { deviceId, publicKeyPrimary } = request;

        // 1. Get Entropy from Identity Service (AKV)
        const entropy = await this.identityService.getEntropy(deviceId);

        // 2. Derive Primary Key (Identity-linked + Nonce)
        const primaryNonce = crypto.randomBytes(32);
        const backendPrimaryPair = this.cryptoProvider.deriveKeyPairFromEntropy(entropy, primaryNonce);

        // 3. Generate Ephemeral KeyPair
        const backendEphemeralPair = this.cryptoProvider.generateKeyPair();

        // 4. Compute Shared Secret
        const sharedSecretPrimary = this.cryptoProvider.computeSharedSecret(
            backendPrimaryPair.privateKey,
            publicKeyPrimary
        );

        const kid = uuidv4();

        // 5. Manage Session Uniqueness & Storage
        const oldKid = await this.sessionRepository.getLastKid(deviceId);

        if (oldKid) {
            await this.sessionRepository.setKeyExpiry(REDIS_KEYS.EPHEMERAL_PREFIX + oldKid, 300);
        }

        const ttl = 24 * 60 * 60; // 24h
        await Promise.all([
            this.sessionRepository.storePrimarySecret(deviceId, sharedSecretPrimary, ttl),
            this.sessionRepository.storeEphemeralPrivateKey(kid, backendEphemeralPair.privateKey, ttl),
            this.sessionRepository.storeLastKidMapping(deviceId, kid, ttl)
        ]);

        return {
            publicKeyPrimary: this.cryptoProvider.exportPublicKeyToPEM(backendPrimaryPair.publicKey),
            publicKeyEphemeral: this.cryptoProvider.exportPublicKeyToPEM(backendEphemeralPair.publicKey),
            kid
        };
    }
}
