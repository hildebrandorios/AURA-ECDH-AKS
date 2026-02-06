import { LocalKeyAdapter } from '../../src/infrastructure/adapters/local-key.adapter';
import { ERROR_MESSAGES, STRINGS } from '../../src/config/string-constants';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

jest.mock('fs');

describe('LocalKeyAdapter', () => {
    let adapter: LocalKeyAdapter;
    const { privateKey: ecPriv, publicKey: ecPub } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const mockEccPrivateKey = ecPriv.export({ type: 'pkcs8', format: 'pem' }) as string;

    const { privateKey: rsaPriv, publicKey: rsaPub } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });
    const mockRsaPrivateKey = rsaPriv.export({ type: 'pkcs1', format: 'pem' }) as string;
    const mockRsaPublicKey = rsaPub.export({ type: 'spki', format: 'pem' }) as string;

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should initialize correctly with direct values', async () => {
        adapter = new LocalKeyAdapter(mockEccPrivateKey, mockRsaPrivateKey);
        await adapter.initialize();
        expect(adapter.getEntropy().trim()).toBe(mockEccPrivateKey.trim());
        expect((await adapter.getRSAPublicKey()).trim()).toBe(mockRsaPublicKey.trim());
    });

    it('should initialize correctly with file paths', async () => {
        const eccPath = './keys/ecc.key';
        const rsaPath = './keys/rsa.key';

        (fs.existsSync as jest.Mock).mockReturnValue(true);
        (fs.lstatSync as jest.Mock).mockReturnValue({ isFile: () => true });
        (fs.readFileSync as jest.Mock).mockImplementation((p: string) => {
            if (p.includes('ecc')) return mockEccPrivateKey;
            if (p.includes('rsa')) return mockRsaPrivateKey;
            return '';
        });

        adapter = new LocalKeyAdapter(eccPath, rsaPath);
        await adapter.initialize();

        expect(fs.existsSync).toHaveBeenCalledTimes(2);
        expect(adapter.getEntropy().trim()).toBe(mockEccPrivateKey.trim());
    });

    it('should throw error if ECC key is missing', async () => {
        adapter = new LocalKeyAdapter('', mockRsaPrivateKey);
        await expect(adapter.initialize()).rejects.toThrow(`${ERROR_MESSAGES.KEY_ERROR}: ${STRINGS.ERR_ECC_KEY_NOT_FOUND}`);
    });

    it('should throw error if RSA key is missing', async () => {
        adapter = new LocalKeyAdapter(mockEccPrivateKey, '');
        await expect(adapter.initialize()).rejects.toThrow(ERROR_MESSAGES.KEY_ERROR);
    });

    it('should decrypt RSA', async () => {
        adapter = new LocalKeyAdapter(mockEccPrivateKey, mockRsaPrivateKey);
        await adapter.initialize();

        const plaintext = "Hello World";
        const buffer = Buffer.from(plaintext, 'utf8');
        const encrypted = crypto.publicEncrypt({
            key: mockRsaPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, buffer);
        const encryptedB64 = encrypted.toString('base64');

        const decrypted = await adapter.decryptRSA(encryptedB64);
        expect(decrypted).toBe(plaintext);
    });

    it('should encrypt RSA Private (sign)', async () => {
        adapter = new LocalKeyAdapter(mockEccPrivateKey, mockRsaPrivateKey);
        await adapter.initialize();

        const plaintext = "Hello World";
        const encryptedB64 = adapter.encryptRSAPrivate(plaintext);

        const decryptedBuffer = crypto.publicDecrypt({
            key: mockRsaPublicKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
        }, Buffer.from(encryptedB64, 'base64'));

        expect(decryptedBuffer.toString('utf8')).toBe(plaintext);
    });

});
