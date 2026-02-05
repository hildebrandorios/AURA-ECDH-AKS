jest.mock('uuid', () => ({ v4: () => 'mocked-uuid' }));
import { PerformHandshake } from '../../src/application/use-cases/perform-handshake.use-case';
import { ICryptoProvider } from '../../src/domain/interfaces/crypto-provider.interface';
import { IIdentityService } from '../../src/domain/interfaces/identity-service.interface';
import { ISessionRepository } from '../../src/domain/interfaces/session-repository.interface';
import { CryptoCurve, REDIS_KEYS } from '../../src/config/constants';

describe('PerformHandshake Use Case', () => {
    let cryptoProvider: jest.Mocked<ICryptoProvider>;
    let identityService: jest.Mocked<IIdentityService>;
    let sessionRepository: jest.Mocked<ISessionRepository>;
    let useCase: PerformHandshake;

    beforeEach(() => {
        cryptoProvider = {
            generateKeyPair: jest.fn(),
            deriveKeyPairFromEntropy: jest.fn(),
            computeSharedSecret: jest.fn(),
            validatePublicKey: jest.fn(),
            exportPublicKeyToPEM: jest.fn(),
            encryptAESGCM: jest.fn(),
            decryptAESGCM: jest.fn(),
            encryptRSA: jest.fn(),
            decryptRSA: jest.fn(),
            deriveMessageKey: jest.fn(),
        } as any;

        identityService = {
            getEntropy: jest.fn(),
            decryptRSA: jest.fn(),
            getRSAPublicKey: jest.fn(),
            encryptRSAPrivate: jest.fn()
        } as any;

        sessionRepository = {
            storePrimarySecret: jest.fn(),
            storeEphemeralPrivateKey: jest.fn(),
            storeLastKidMapping: jest.fn(),
            getLastKid: jest.fn(),
            getPrimarySecret: jest.fn(),
            getEphemeralPrivateKey: jest.fn(),
            setKeyExpiry: jest.fn()
        } as any;

        useCase = new PerformHandshake(cryptoProvider, identityService, sessionRepository);
    });

    it('should successfully perform a handshake', async () => {
        const deviceId = '550e8400-e29b-41d4-a716-446655440000';
        const publicKeyPrimary = 'client-key';

        // Generamos PEM reales para evitar errores en pemToHex
        const { generateKeyPairSync } = require('node:crypto');
        const { publicKey: realPub } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
        const validPEM = realPub.export({ type: 'spki', format: 'pem' });

        identityService.decryptRSA.mockResolvedValue(publicKeyPrimary);
        identityService.encryptRSAPrivate.mockReturnValue('enc-res');
        identityService.getEntropy.mockReturnValue('entropy-hex');

        cryptoProvider.deriveKeyPairFromEntropy.mockReturnValue({
            privateKey: 'backend-primary-priv',
            publicKey: 'backend-primary-pub'
        });
        cryptoProvider.generateKeyPair.mockReturnValue({
            privateKey: 'backend-eph-priv',
            publicKey: 'backend-eph-pub'
        });
        cryptoProvider.computeSharedSecret.mockReturnValue('shared-secret');
        cryptoProvider.exportPublicKeyToPEM.mockReturnValue(validPEM);
        sessionRepository.getLastKid.mockResolvedValue(null);

        const result = await useCase.execute({
            deviceId: deviceId,
            publicKeyPrimary: 'enc-key'
        });

        expect(result).toEqual({
            publicKeyPrimary: 'enc-res',
            publicKeyEphemeral: 'enc-res',
            kid: expect.any(String)
        });

        expect(identityService.decryptRSA).toHaveBeenCalledWith('enc-key');
        expect(identityService.encryptRSAPrivate).toHaveBeenCalledTimes(2);
        expect(cryptoProvider.computeSharedSecret).toHaveBeenCalledWith(
            expect.any(String),
            'client-key',
            CryptoCurve.SECP256K1
        );
    });

    it('should rotate old KID if it exists', async () => {
        const deviceId = '550e8400-e29b-41d4-a716-446655440000';

        const { generateKeyPairSync } = require('node:crypto');
        const { publicKey: realPub } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
        const validPEM = realPub.export({ type: 'spki', format: 'pem' });

        identityService.decryptRSA.mockResolvedValue('key');
        identityService.encryptRSAPrivate.mockReturnValue('enc');
        sessionRepository.getLastKid.mockResolvedValue('old-kid');
        identityService.getEntropy.mockReturnValue('entropy');
        cryptoProvider.deriveKeyPairFromEntropy.mockReturnValue({ privateKey: 'p', publicKey: 'p' });
        cryptoProvider.generateKeyPair.mockReturnValue({ privateKey: 'e', publicKey: 'e' });
        cryptoProvider.exportPublicKeyToPEM.mockReturnValue(validPEM);

        await useCase.execute({ deviceId: deviceId, publicKeyPrimary: 'enc-k' });

        expect(sessionRepository.setKeyExpiry).toHaveBeenCalledWith(REDIS_KEYS.EPHEMERAL_PREFIX + 'old-kid', 300);
    });
});
