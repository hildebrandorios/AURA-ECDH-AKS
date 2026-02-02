jest.mock('uuid', () => ({ v4: () => 'mocked-uuid' }));
import { PerformHandshake } from '../perform-handshake.use-case';
import { ICryptoProvider } from '../../../domain/interfaces/crypto-provider.interface';
import { IIdentityService } from '../../../domain/interfaces/identity-service.interface';
import { ISessionRepository } from '../../../domain/interfaces/session-repository.interface';

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
            deriveMessageKey: jest.fn(),
        } as any;

        identityService = {
            getEntropy: jest.fn()
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

        identityService.getEntropy.mockResolvedValue('entropy-hex');
        cryptoProvider.deriveKeyPairFromEntropy.mockReturnValue({
            privateKey: 'backend-primary-priv',
            publicKey: 'backend-primary-pub'
        });
        cryptoProvider.generateKeyPair.mockReturnValue({
            privateKey: 'backend-eph-priv',
            publicKey: 'backend-eph-pub'
        });
        cryptoProvider.computeSharedSecret.mockReturnValue('shared-secret');
        cryptoProvider.exportPublicKeyToPEM.mockReturnValue('pem-key');
        sessionRepository.getLastKid.mockResolvedValue(null);

        const result = await useCase.execute({ deviceId, publicKeyPrimary });

        expect(result).toEqual({
            publicKeyPrimary: 'pem-key',
            publicKeyEphemeral: 'pem-key',
            kid: expect.any(String)
        });

        expect(identityService.getEntropy).toHaveBeenCalledWith(deviceId);
        expect(sessionRepository.storePrimarySecret).toHaveBeenCalled();
        expect(sessionRepository.storeEphemeralPrivateKey).toHaveBeenCalled();
    });

    it('should rotate old KID if it exists', async () => {
        const deviceId = '550e8400-e29b-41d4-a716-446655440000';
        sessionRepository.getLastKid.mockResolvedValue('old-kid');

        identityService.getEntropy.mockResolvedValue('entropy');
        cryptoProvider.deriveKeyPairFromEntropy.mockReturnValue({ privateKey: 'p', publicKey: 'p' });
        cryptoProvider.generateKeyPair.mockReturnValue({ privateKey: 'e', publicKey: 'e' });
        cryptoProvider.exportPublicKeyToPEM.mockReturnValue('pem');

        await useCase.execute({ deviceId, publicKeyPrimary: 'key' });

        expect(sessionRepository.setKeyExpiry).toHaveBeenCalledWith('handshake:eph:old-kid', 300);
    });
});
