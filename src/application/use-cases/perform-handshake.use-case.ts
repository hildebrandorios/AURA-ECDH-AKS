import { CRYPTO, CryptoCurve, REDIS_KEYS, TTL } from "../../config/constants";
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
        const deviceId = request.deviceId;
        const publicKeyPrimary = await this.identityService.decryptRSA(request.publicKeyPrimary);
        const entropy = this.identityService.getEntropy();

        const primaryNonce = nodeCrypto.randomBytes(CRYPTO.NONCE_BYTES);
        const backendPrimaryPair = this.cryptoProvider.deriveKeyPairFromEntropy(entropy, primaryNonce);
        const backendEphemeralPair = this.cryptoProvider.generateKeyPair(CryptoCurve.X25519);

        const sharedSecretPrimary = this.cryptoProvider.computeSharedSecret(
            backendPrimaryPair.privateKey,
            publicKeyPrimary,
            CryptoCurve.SECP256K1
        );

        const kid = uuidv4();
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

        return {
            publicKeyPrimary: this.identityService.encryptRSAPrivate(backendPrimaryPair.publicKey),
            publicKeyEphemeral: this.identityService.encryptRSAPrivate(backendEphemeralPair.publicKey),
            kid,
            duration: 0
        };
    }
}
