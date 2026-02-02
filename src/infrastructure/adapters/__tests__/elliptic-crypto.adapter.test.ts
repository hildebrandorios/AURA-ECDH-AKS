import { EllipticCryptoAdapter } from '../elliptic-crypto.adapter';
import { createPublicKey } from 'crypto';

describe('EllipticCryptoAdapter', () => {
    const adapter = new EllipticCryptoAdapter();
    const keyPair = adapter.generateKeyPair();

    it('should validate valid public keys', () => {
        expect(adapter.validatePublicKey(keyPair.publicKey)).toBe(true);
    });

    it('should derive a key pair from entropy and salt', () => {
        const entropy = '00'.repeat(32);
        const salt = Buffer.alloc(32, 1);
        const pair = adapter.deriveKeyPairFromEntropy(entropy, salt);

        expect(pair).toHaveProperty('privateKey');
        const pair2 = adapter.deriveKeyPairFromEntropy(entropy, salt);
        expect(pair2.privateKey).toBe(pair.privateKey);
    });

    it('should export public key to PEM', () => {
        const pem = adapter.exportPublicKeyToPEM(keyPair.publicKey);
        expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
        const keyObject = createPublicKey(pem);
        expect(keyObject.asymmetricKeyType).toBe('ec');
    });

    it('should handle invalid public keys gracefully', () => {
        expect(adapter.validatePublicKey('invalid')).toBe(false);
        expect(() => adapter.computeSharedSecret(keyPair.privateKey, 'invalid')).toThrow();
    });

    it('should normalize PEM keys to hex correctly', () => {
        const pem = adapter.exportPublicKeyToPEM(keyPair.publicKey);
        const secret = adapter.computeSharedSecret(keyPair.privateKey, pem);
        expect(secret).toBeDefined();
    });

    it('should handle base64 public keys correctly', () => {
        const base64 = Buffer.from(keyPair.publicKey, 'hex').toString('base64');
        expect(adapter.validatePublicKey(base64)).toBe(true);

        // Invalid length base64
        const shortBase64 = Buffer.from('abc').toString('base64');
        expect(adapter.validatePublicKey(shortBase64)).toBe(false);
    });

    it('should return false for random strings that are not keys', () => {
        expect(adapter.validatePublicKey('not-a-key-at-all-!!!!!')).toBe(false);
    });

    it('should derive message key correctly', () => {
        const k1 = '0'.repeat(64);
        const k2 = '1'.repeat(64);
        const derived = adapter.deriveMessageKey(k1, k2);
        expect(derived).toBeDefined();
        expect(derived.length).toBe(64);
    });

    it('should encrypt and decrypt using AES-GCM', () => {
        const key = 'a'.repeat(64);
        const plaintext = 'Secret message';

        const encrypted = adapter.encryptAESGCM(key, plaintext);
        expect(encrypted.payload).toBeDefined();
        expect(encrypted.iv).toBeDefined();
        expect(encrypted.tag).toBeDefined();

        const decrypted = adapter.decryptAESGCM(key, encrypted.payload, encrypted.iv, encrypted.tag);
        expect(decrypted).toBe(plaintext);
    });
});
