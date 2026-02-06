import { ProcessEncryptedData } from '../../src/application/use-cases/process-encrypted-data.use-case';
import { ICryptoProvider } from '../../src/domain/interfaces/crypto-provider.interface';
import { ISessionRepository } from '../../src/domain/interfaces/session-repository.interface';
import { Encoding } from '../../src/config/constants';
import { ERROR_MESSAGES } from '../../src/config/string-constants';

jest.mock('uuid', () => ({ v4: () => 'new-mocked-kid' }));

describe('ProcessEncryptedData Use Case', () => {
    let useCase: ProcessEncryptedData;
    let mockCryptoProvider: jest.Mocked<ICryptoProvider>;
    let mockSessionRepository: jest.Mocked<ISessionRepository>;

    const encodeEncrypted = (iv: string, tag: string, payload: string) => {
        return Buffer.concat([
            Buffer.from(iv, Encoding.HEX),
            Buffer.from(tag, Encoding.HEX),
            Buffer.from(payload, Encoding.HEX)
        ]).toString(Encoding.BASE64);
    };

    beforeEach(() => {
        mockCryptoProvider = {
            generateKeyPair: jest.fn(),
            deriveKeyPairFromEntropy: jest.fn(),
            computeSharedSecret: jest.fn(),
            validatePublicKey: jest.fn(),
            exportPublicKeyToPEM: jest.fn(),
            encryptAESGCM: jest.fn(),
            decryptAESGCM: jest.fn(),
            deriveMessageKey: jest.fn(),
        } as any;

        mockSessionRepository = {
            storePrimarySecret: jest.fn(),
            storeEphemeralPrivateKey: jest.fn(),
            storeLastKidMapping: jest.fn(),
            getLastKid: jest.fn(),
            getPrimarySecret: jest.fn(),
            getEphemeralPrivateKey: jest.fn(),
            setKeyExpiry: jest.fn(),
        } as any;

        useCase = new ProcessEncryptedData(mockCryptoProvider, mockSessionRepository);
    });

    it('should process encrypted data successfully with optimized Base64 format', async () => {
        const clientEphB64 = encodeEncrypted('01'.repeat(12), '02'.repeat(16), '03'.repeat(32));
        const encryptedDataB64 = encodeEncrypted('04'.repeat(12), '05'.repeat(16), '06'.repeat(32));

        const request = {
            deviceId: 'device-123',
            kid: 'old-kid',
            publicKeyEphemeral: clientEphB64,
            encryptedData: encryptedDataB64
        };

        mockSessionRepository.getPrimarySecret.mockResolvedValue('primary-secret-hex');
        mockSessionRepository.getEphemeralPrivateKey.mockResolvedValue('old-ephemeral-priv-key');

        mockCryptoProvider.decryptAESGCM.mockImplementation((key, payload) => {
            if (key === 'primary-secret-hex' && payload === '03'.repeat(32)) return 'client-eph-pem';
            if (key === 'km-hex' && payload === '06'.repeat(32)) return '{"data":"hello"}';
            return '';
        });

        mockCryptoProvider.computeSharedSecret.mockReturnValue('ss-e-hex');
        mockCryptoProvider.deriveMessageKey.mockReturnValue('km-hex');

        const nextKeyPair = { privateKey: 'next-priv', publicKey: 'next-pub' };
        mockCryptoProvider.generateKeyPair.mockReturnValue(nextKeyPair);
        mockCryptoProvider.exportPublicKeyToPEM.mockReturnValue('next-pub-pem');

        mockCryptoProvider.encryptAESGCM.mockImplementation((key, plaintext) => {
            if (key === 'km-hex') return { payload: 'res-hex', iv: 'iv-res-hex', tag: 'tag-res-hex' };
            if (key === 'primary-secret-hex' && plaintext === 'next-pub') return { payload: 'next-eph-hex', iv: 'iv-next-hex', tag: 'tag-next-hex' };
            return { payload: '', iv: '', tag: '' };
        });

        const result = await useCase.execute(request);

        expect(mockSessionRepository.getPrimarySecret).toHaveBeenCalledWith('device-123');
        expect(mockCryptoProvider.decryptAESGCM).toHaveBeenCalledWith('primary-secret-hex', '03'.repeat(32), '01'.repeat(12), '02'.repeat(16));
        expect(mockCryptoProvider.deriveMessageKey).toHaveBeenCalledWith('primary-secret-hex', 'ss-e-hex', 'device-123');

        // El resultado debe estar en Base64
        expect(typeof result.encryptedData).toBe('string');
        expect(typeof result.publicKeyEphemeral).toBe('string');
        expect(result.kid).toBe('new-mocked-kid');
    });

    it('should throw 401 if secrets are missing', async () => {
        mockSessionRepository.getPrimarySecret.mockResolvedValue(null);
        await expect(useCase.execute({} as any)).rejects.toThrow('401');
    });

    it('should throw if publicKeyEphemeral decryption fails', async () => {
        mockSessionRepository.getPrimarySecret.mockResolvedValue('ps');
        mockSessionRepository.getEphemeralPrivateKey.mockResolvedValue('epk');
        mockCryptoProvider.decryptAESGCM.mockImplementationOnce(() => { throw new Error('Decryption Failed'); });

        await expect(useCase.execute({
            deviceId: 'd', kid: 'k',
            publicKeyEphemeral: encodeEncrypted('01'.repeat(12), '02'.repeat(16), '03'.repeat(32)),
            encryptedData: 'e'
        } as any)).rejects.toThrow(ERROR_MESSAGES.DECRYPTION_FAILED);
    });

    it('should throw if payload decryption fails', async () => {
        mockSessionRepository.getPrimarySecret.mockResolvedValue('ps');
        mockSessionRepository.getEphemeralPrivateKey.mockResolvedValue('epk');
        // First decrypt (clientEph) succeeds
        mockCryptoProvider.decryptAESGCM.mockReturnValueOnce('client-eph-pem');
        mockCryptoProvider.computeSharedSecret.mockReturnValue('ss');
        mockCryptoProvider.deriveMessageKey.mockReturnValue('km');
        // Second decrypt (payload) fails
        mockCryptoProvider.decryptAESGCM.mockImplementationOnce(() => { throw new Error('Payload Decryption Failed'); });

        await expect(useCase.execute({
            deviceId: 'd', kid: 'k',
            publicKeyEphemeral: encodeEncrypted('01'.repeat(12), '02'.repeat(16), '03'.repeat(32)),
            encryptedData: encodeEncrypted('04'.repeat(12), '05'.repeat(16), '06'.repeat(32))
        } as any)).rejects.toThrow(ERROR_MESSAGES.DECRYPTION_FAILED);
    });
});
