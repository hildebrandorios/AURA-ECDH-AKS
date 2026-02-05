import { DefaultAzureCredential } from '@azure/identity';
import { KeyClient, CryptographyClient } from '@azure/keyvault-keys';
import { SecretClient } from '@azure/keyvault-secrets';
import { AzureKeyVaultAdapter } from '../../src/infrastructure/adapters/key-vault.adapter';
import { generateKeyPairSync, publicEncrypt, constants } from 'node:crypto';
import { Encoding, ERROR_MESSAGES } from '../../src/config/constants';

jest.mock('@azure/identity');
jest.mock('@azure/keyvault-keys');
jest.mock('@azure/keyvault-secrets');

describe('AzureKeyVaultAdapter', () => {
    let adapter: AzureKeyVaultAdapter;
    const vaultUrl = 'https://test.vault.azure.net';
    const masterKeyName = 'master-ecc-key';
    const rsaKeyName = 'rsa-secret-key';

    // Claves reales para derivación local en tests
    const { publicKey: mockPubKey, privateKey: mockPrivKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    beforeEach(() => {
        jest.clearAllMocks();
        delete process.env.RSA_PRIVATE_KEY;

        (DefaultAzureCredential as jest.Mock).mockImplementation(() => ({}));

        (KeyClient as jest.Mock).mockImplementation(() => ({
            getKey: jest.fn().mockResolvedValue({ id: 'mock-key-id' })
        }));

        (CryptographyClient as jest.Mock).mockImplementation(() => ({
            signData: jest.fn().mockResolvedValue({ result: Buffer.from('mock-signature') })
        }));

        (SecretClient as jest.Mock).mockImplementation(() => ({
            getSecret: jest.fn().mockRejectedValue(new Error('Not found'))
        }));

        adapter = new AzureKeyVaultAdapter(vaultUrl, masterKeyName, rsaKeyName);
    });

    it('should initialize entropy and RSA keys (from environment fallback)', async () => {
        process.env.RSA_PRIVATE_KEY = mockPrivKey as string;

        await adapter.initialize();

        expect(adapter.getEntropy()).toBe(Buffer.from('mock-signature').toString(Encoding.HEX));
        const pubKey = await adapter.getRSAPublicKey();
        expect(pubKey).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should initialize and prioritize RSA key from Key Vault Secret', async () => {
        (SecretClient as jest.Mock).mockImplementation(() => ({
            getSecret: jest.fn().mockResolvedValue({ value: mockPrivKey })
        }));

        // Re-instanciar para que tome el nuevo mock del constructor
        const secretAdapter = new AzureKeyVaultAdapter(vaultUrl, masterKeyName, rsaKeyName);
        await secretAdapter.initialize();

        const pubKey = await secretAdapter.getRSAPublicKey();
        expect(pubKey).toBeDefined();
        expect(SecretClient).toHaveBeenCalled();
    });

    it('should throw critical error if no RSA key is found anywhere', async () => {
        await expect(adapter.initialize()).rejects.toThrow(ERROR_MESSAGES.KEY_VAULT_ERROR);
    });

    it('should throw error if RSA private key is invalid', async () => {
        process.env.RSA_PRIVATE_KEY = 'invalid-pem-content';
        await expect(adapter.initialize()).rejects.toThrow(ERROR_MESSAGES.KEY_VAULT_ERROR);
    });

    it('should decrypt RSA data correctly in memory', async () => {
        process.env.RSA_PRIVATE_KEY = mockPrivKey as string;
        await adapter.initialize();

        const plaintext = "secret-message";
        const encrypted = publicEncrypt({
            key: mockPubKey,
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, Buffer.from(plaintext, Encoding.UTF8)).toString(Encoding.BASE64);

        const result = await adapter.decryptRSA(encrypted);
        expect(result).toBe(plaintext);
    });

    it('should throw error during decrypt if not initialized', async () => {
        await expect(adapter.decryptRSA('any')).rejects.toThrow('RSA Private Key not loaded.');
    });

    it('should encrypt with private key (authenticity) correctly', async () => {
        process.env.RSA_PRIVATE_KEY = mockPrivKey as string;
        await adapter.initialize();

        const plaintext = "verify-me";
        const encrypted = adapter.encryptRSAPrivate(plaintext);

        const { publicDecrypt, constants: cryptoConstants } = require('node:crypto');
        const decrypted = publicDecrypt({
            key: mockPubKey,
            padding: cryptoConstants.RSA_PKCS1_PADDING
        }, Buffer.from(encrypted, Encoding.BASE64)).toString(Encoding.UTF8);

        expect(decrypted).toBe(plaintext);
    });

    it('should throw error if getEntropy is called before initialize', () => {
        expect(() => adapter.getEntropy()).toThrow('IdentityService not initialized');
    });
});
