import { NativeCryptoAdapter } from '../../src/infrastructure/adapters/native-crypto.adapter';
import { KeyPair } from '../../src/domain/interfaces/crypto-provider.interface';
import { CryptoCurve } from '../../src/config/constants';

describe('NativeCryptoAdapter', () => {
    let adapter: NativeCryptoAdapter;
    let keyPair: KeyPair;

    beforeEach(() => {
        adapter = new NativeCryptoAdapter();
        keyPair = adapter.generateKeyPair();
    });

    it('should generate a valid key pair', () => {
        expect(keyPair).toHaveProperty('privateKey');
        expect(keyPair).toHaveProperty('publicKey');
        expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should validate a correct public key in PEM format', () => {
        expect(adapter.validatePublicKey(keyPair.publicKey)).toBe(true);
    });

    it('should validate a correct public key in hex format', () => {
        // Need to extract hex from PEM or use raw hex
        const hexKey = '04' + '00'.repeat(64);
        expect(adapter.validatePublicKey(hexKey)).toBe(true);
    });

    it('should handle compressed keys in validatePublicKey', () => {
        const compressed02 = '02' + '00'.repeat(32);
        const compressed03 = '03' + '00'.repeat(32);
        expect(adapter.validatePublicKey(compressed02)).toBe(true);
        expect(adapter.validatePublicKey(compressed03)).toBe(true);
    });

    it('should return false for random strings that are not keys', () => {
        expect(adapter.validatePublicKey('random-string')).toBe(false);
        expect(adapter.validatePublicKey('04' + 'zz'.repeat(64))).toBe(false); // Invalid hex
        expect(adapter.validatePublicKey('02' + '00'.repeat(31))).toBe(false); // Wrong length
        expect(adapter.validatePublicKey('05' + '00'.repeat(32))).toBe(false); // Wrong prefix
        expect(adapter.validatePublicKey(null as any)).toBe(false); // Catch branch
    });

    it('should derive key pair from hex entropy', () => {
        const entropy = '0123456789abcdef0123456789abcdef';
        const salt = Buffer.from('salt');
        const derived = adapter.deriveKeyPairFromEntropy(entropy, salt);
        expect(derived.privateKey).toBeDefined();
        expect(derived.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should derive key pair from non-hex entropy (utf8 branch)', () => {
        const entropy = 'some-string-entropy';
        const salt = Buffer.from('salt');
        const derived = adapter.deriveKeyPairFromEntropy(entropy, salt);
        expect(derived.privateKey).toBeDefined();
    });

    it('should compute shared secret correctly', () => {
        const kp2 = adapter.generateKeyPair();
        const secret1 = adapter.computeSharedSecret(keyPair.privateKey, kp2.publicKey);
        const secret2 = adapter.computeSharedSecret(kp2.privateKey, keyPair.publicKey);
        expect(secret1).toBe(secret2);
    });

    it('should compute message key correctly using HKDF and salt', () => {
        const key = adapter.deriveMessageKey('01'.repeat(32), '02'.repeat(32), 'device-1');
        expect(key).toHaveLength(64);

        // Verify deterministic behavior
        const key2 = adapter.deriveMessageKey('01'.repeat(32), '02'.repeat(32), 'device-1');
        expect(key).toBe(key2);

        // Verify different salts produce different keys
        const key3 = adapter.deriveMessageKey('01'.repeat(32), '02'.repeat(32), 'device-2');
        expect(key).not.toBe(key3);

        // Verify different inputs produce different keys
        const key4 = adapter.deriveMessageKey('01'.repeat(32), '03'.repeat(32), 'device-1');
        expect(key).not.toBe(key4);
    });

    it('should encrypt and decrypt correctly', () => {
        const key = '01'.repeat(32);
        const plaintext = 'hello world';
        const encrypted = adapter.encryptAESGCM(key, plaintext);
        const decrypted = adapter.decryptAESGCM(key, encrypted.payload, encrypted.iv, encrypted.tag);
        expect(decrypted).toBe(plaintext);
    });

    it('should throw error on invalid shared secret computation', () => {
        expect(() => adapter.computeSharedSecret('invalid-priv', 'invalid-pub')).toThrow();
        // Force crypto error for branch coverage
        expect(() => adapter.computeSharedSecret('00'.repeat(32), '00'.repeat(32))).toThrow();
    });

    it('should handle X25519 keys in validatePublicKey', () => {
        const x25519Key = '00'.repeat(32);
        expect(adapter.validatePublicKey(x25519Key, CryptoCurve.X25519)).toBe(true);
        expect(adapter.validatePublicKey(x25519Key, CryptoCurve.SECP256K1)).toBe(false);
    });

    it('should generate a valid X25519 key pair', () => {
        const kp = adapter.generateKeyPair(CryptoCurve.X25519);
        expect(kp.curve).toBe(CryptoCurve.X25519);
        expect(kp.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should compute X25519 shared secret correctly', () => {
        const kp1 = adapter.generateKeyPair(CryptoCurve.X25519);
        const kp2 = adapter.generateKeyPair(CryptoCurve.X25519);
        const s1 = adapter.computeSharedSecret(kp1.privateKey, kp2.publicKey, CryptoCurve.X25519);
        const s2 = adapter.computeSharedSecret(kp2.privateKey, kp1.publicKey, CryptoCurve.X25519);
        expect(s1).toBe(s2);
    });

    it('should encrypt and decrypt RSA correctly', () => {
        const { generateKeyPairSync } = require('node:crypto');
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const plaintext = "rsa-secret-message";
        const encrypted = adapter.encryptRSA(publicKey, plaintext);
        const decrypted = adapter.decryptRSA(privateKey, encrypted);
        expect(decrypted).toBe(plaintext);
    });

    it('should handle normalization errors', () => {
        expect((adapter as any).normalizeKeyToHex('!!!')).toBe(null);
    });
});
