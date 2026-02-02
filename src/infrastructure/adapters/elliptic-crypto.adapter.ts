import { ICryptoProvider, KeyPair } from "../../domain/interfaces/crypto-provider.interface";
import { ec as EC } from 'elliptic';
import { createPublicKey, createHash } from 'crypto';
import * as nodeCrypto from 'crypto';
import { CRYPTO } from '../../config/constants';

const ec = new EC(CRYPTO.CURVE);

export class EllipticCryptoAdapter implements ICryptoProvider {

    public validatePublicKey(publicKeyInput: string): boolean {
        try {
            const hex = this.normalizeKeyToHex(publicKeyInput);
            if (!hex) return false;
            const key = ec.keyFromPublic(hex, 'hex');
            return key.validate().result;
        } catch (e) {
            return false;
        }
    }

    public generateKeyPair(): KeyPair {
        const key = ec.genKeyPair();
        return {
            privateKey: key.getPrivate('hex'),
            publicKey: key.getPublic(true, 'hex')
        };
    }

    public deriveKeyPairFromEntropy(entropy: string, salt: Buffer): KeyPair {
        const hash = createHash(CRYPTO.HASH_ALGORITHM);
        // Si es hex, lo usamos como binario, si no, como UTF-8
        if (/^[0-9a-fA-F]+$/.test(entropy) && entropy.length % 2 === 0) {
            hash.update(Buffer.from(entropy, 'hex'));
        } else {
            hash.update(Buffer.from(entropy, 'utf8'));
        }
        hash.update(salt);
        const privateKeyHex = hash.digest('hex');
        const key = ec.keyFromPrivate(privateKeyHex, 'hex');
        return {
            privateKey: privateKeyHex,
            publicKey: key.getPublic(true, 'hex')
        };
    }

    public computeSharedSecret(privateKeyHex: string, otherPublicKeyInput: string): string {
        const otherHex = this.normalizeKeyToHex(otherPublicKeyInput);
        if (!otherHex) throw new Error("Invalid public key format");
        const key1 = ec.keyFromPrivate(privateKeyHex, 'hex');
        const key2 = ec.keyFromPublic(otherHex, 'hex');
        return key1.derive(key2.getPublic()).toString(16).padStart(64, '0');
    }

    public exportPublicKeyToPEM(publicKeyHex: string): string {
        const key = ec.keyFromPublic(publicKeyHex, 'hex');
        const pub = key.getPublic();
        const x = Buffer.from(pub.getX().toArray('be', 32)).toString('base64url');
        const y = Buffer.from(pub.getY().toArray('be', 32)).toString('base64url');
        const jwk = { kty: CRYPTO.KEY_TYPE, crv: CRYPTO.CURVE, x, y };
        const keyObject = createPublicKey({ key: jwk as any, format: 'jwk' });
        return keyObject.export({ type: 'spki', format: 'pem' }) as string;
    }

    public deriveMessageKey(primarySecretHex: string, ephemeralSecretHex: string): string {
        const hash = createHash('sha256');
        hash.update(Buffer.from(primarySecretHex, 'hex'));
        hash.update(Buffer.from(ephemeralSecretHex, 'hex'));
        return hash.digest('hex');
    }

    public encryptAESGCM(keyHex: string, plaintext: string): { payload: string; iv: string; tag: string } {
        const iv = nodeCrypto.randomBytes(12);
        const cipher = nodeCrypto.createCipheriv(CRYPTO.ENCRYPTION_ALGORITHM, Buffer.from(keyHex, 'hex'), iv);

        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const tag = cipher.getAuthTag().toString('hex');

        return {
            payload: encrypted,
            iv: iv.toString('hex'),
            tag: tag
        };
    }

    public decryptAESGCM(keyHex: string, payloadHex: string, ivHex: string, tagHex: string): string {
        const decipher = nodeCrypto.createDecipheriv(
            CRYPTO.ENCRYPTION_ALGORITHM,
            Buffer.from(keyHex, 'hex'),
            Buffer.from(ivHex, 'hex')
        );

        decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

        let decrypted = decipher.update(payloadHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    private normalizeKeyToHex(input: string): string | null {
        try {
            if (/^[0-9a-fA-F]+$/.test(input)) return input;
            const keyObject = createPublicKey(input);
            const jwk = keyObject.export({ format: 'jwk' });
            if (jwk.kty === CRYPTO.KEY_TYPE && (jwk.crv === CRYPTO.CURVE_ALT || jwk.crv === CRYPTO.CURVE)) {
                const x = Buffer.from(jwk.x!, 'base64url').toString('hex');
                const y = Buffer.from(jwk.y!, 'base64url').toString('hex');
                return '04' + x.padStart(64, '0') + y.padStart(64, '0');
            }
            return null;
        } catch {
            try {
                if (/^[a-zA-Z0-9+/=]+$/.test(input) && !input.includes('-----')) {
                    const buf = Buffer.from(input, 'base64');
                    if (buf.length === 33 || buf.length === 65) return buf.toString('hex');
                }
            } catch { }
            return null;
        }
    }
}
