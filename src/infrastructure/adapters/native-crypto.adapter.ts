import {
    createHash,
    randomBytes,
    createCipheriv,
    createDecipheriv,
    publicEncrypt,
    privateDecrypt,
    generateKeyPairSync,
    createPrivateKey,
    createPublicKey,
    diffieHellman,
    createECDH,
    hkdfSync
} from 'node:crypto';
import { CRYPTO, CryptoCurve, Encoding } from '../../config/constants';
import { ICryptoProvider, KeyPair } from "../../domain/interfaces/crypto-provider.interface";

export class NativeCryptoAdapter implements ICryptoProvider {

    public validatePublicKey(publicKeyInput: string, curve: CryptoCurve = CRYPTO.DEFAULT_CURVE): boolean {
        try {
            const hex = this.normalizeKeyToHex(publicKeyInput);
            if (!hex) return false;

            if (curve === CryptoCurve.X25519) {
                return hex.length === 64;
            }

            if (hex.startsWith('04') && hex.length === 130) {
                return true;
            }

            if ((hex.startsWith('02') || hex.startsWith('03')) && hex.length === 66) {
                return true;
            }

            return false;
        } catch (e) {
            return false;
        }
    }

    public generateKeyPair(curve: CryptoCurve = CRYPTO.DEFAULT_CURVE): KeyPair {
        if (curve === CryptoCurve.X25519) {
            const keyPair = generateKeyPairSync(CryptoCurve.X25519);
            const privHex = keyPair.privateKey.export({ format: 'jwk' }).d!;
            const pubHex = Buffer.from((keyPair.publicKey.export({ format: 'jwk' }) as any).x, Encoding.BASE64URL).toString(Encoding.HEX);

            return {
                privateKey: Buffer.from(privHex, Encoding.BASE64URL).toString(Encoding.HEX),
                publicKey: pubHex,
                curve: CryptoCurve.X25519
            };
        }

        const ecdh = createECDH(CryptoCurve.SECP256K1);
        ecdh.generateKeys();
        const pubHex = ecdh.getPublicKey(Encoding.HEX);

        return {
            privateKey: ecdh.getPrivateKey(Encoding.HEX),
            publicKey: pubHex,
            curve: CryptoCurve.SECP256K1
        };
    }

    public deriveKeyPairFromEntropy(entropy: string, salt: Buffer): KeyPair {
        const hash = createHash(CRYPTO.HASH_ALGORITHM);
        if (/^[0-9a-fA-F]+$/.test(entropy) && entropy.length % 2 === 0) {
            hash.update(Buffer.from(entropy, Encoding.HEX));
        } else {
            hash.update(Buffer.from(entropy, Encoding.UTF8));
        }
        hash.update(salt);
        const privateKeyHex = hash.digest(Encoding.HEX);

        const ecdh = createECDH(CryptoCurve.SECP256K1);
        ecdh.setPrivateKey(Buffer.from(privateKeyHex, Encoding.HEX));
        const publicKeyHex = ecdh.getPublicKey(Encoding.HEX);

        return {
            privateKey: privateKeyHex,
            publicKey: publicKeyHex,
        };
    }

    public computeSharedSecret(privateKeyHex: string, otherPublicKey: string, curve: CryptoCurve = CRYPTO.DEFAULT_CURVE): string {
        try {
            if (curve === CryptoCurve.X25519) {
                const pkcs8Header = Buffer.from('302e020100300506032b656e04220420', Encoding.HEX);
                const der = Buffer.concat([pkcs8Header, Buffer.from(privateKeyHex, Encoding.HEX)]);

                const myPrivKey = createPrivateKey({
                    key: der,
                    format: 'der',
                    type: 'pkcs8'
                });

                let theirPubKeyObj;
                if (otherPublicKey.includes('-----BEGIN')) {
                    theirPubKeyObj = createPublicKey(otherPublicKey);
                } else {
                    const hex = this.normalizeKeyToHex(otherPublicKey);
                    if (!hex) throw new Error("Invalid X25519 public key hex");
                    theirPubKeyObj = createPublicKey({
                        key: {
                            kty: 'OKP',
                            crv: 'X25519',
                            x: Buffer.from(hex, Encoding.HEX).toString(Encoding.BASE64URL)
                        },
                        format: 'jwk'
                    });
                }

                return diffieHellman({
                    privateKey: myPrivKey,
                    publicKey: theirPubKeyObj
                }).toString(Encoding.HEX);
            }

            const ecdh = createECDH(CryptoCurve.SECP256K1);
            ecdh.setPrivateKey(Buffer.from(privateKeyHex, Encoding.HEX));

            const hex = this.normalizeKeyToHex(otherPublicKey);
            if (!hex) throw new Error("Invalid public key format");
            const otherKeyBuffer = Buffer.from(hex, Encoding.HEX);

            return ecdh.computeSecret(otherKeyBuffer).toString(Encoding.HEX);
        } catch (e: any) {
            throw new Error(`Failed to compute shared secret: ${e.message}`);
        }
    }

    public encryptRSA(publicKeyPEM: string, plaintext: string): string {
        const buffer = Buffer.from(plaintext, Encoding.UTF8);
        const encrypted = publicEncrypt(publicKeyPEM, buffer);
        return encrypted.toString(Encoding.BASE64);
    }

    public decryptRSA(privateKeyPEM: string, ciphertextB64: string): string {
        const buffer = Buffer.from(ciphertextB64, Encoding.BASE64);
        const decrypted = privateDecrypt(privateKeyPEM, buffer);
        return decrypted.toString(Encoding.UTF8);
    }

    public exportPublicKeyToPEM(publicKeyHex: string, curve: CryptoCurve = CRYPTO.DEFAULT_CURVE): string {
        if (publicKeyHex.includes('-----BEGIN')) return publicKeyHex;

        try {
            if (curve === CryptoCurve.X25519) {
                const jwk = {
                    kty: "OKP",
                    crv: "X25519",
                    x: Buffer.from(publicKeyHex, Encoding.HEX).toString(Encoding.BASE64URL)
                };
                return createPublicKey({ key: jwk as any, format: 'jwk' }).export({ type: 'spki', format: 'pem' }) as string;
            }

            const buffer = Buffer.from(publicKeyHex, Encoding.HEX);
            const x = buffer.subarray(1, 33);
            const y = buffer.subarray(33, 65);

            const jwk = {
                kty: "EC",
                crv: CRYPTO.DEFAULT_CURVE,
                x: x.toString(Encoding.BASE64URL),
                y: y.toString(Encoding.BASE64URL)
            };

            const keyObj = createPublicKey({ key: jwk as any, format: 'jwk' });
            return keyObj.export({ type: 'spki', format: 'pem' }) as string;

        } catch (e: any) {
            throw new Error(`Failed to export to PEM: ${e.message}`);
        }
    }

    public deriveMessageKey(primarySecretHex: string, ephemeralSecretHex: string, salt: string): string {
        const ikm = Buffer.concat([
            Buffer.from(primarySecretHex, Encoding.HEX),
            Buffer.from(ephemeralSecretHex, Encoding.HEX)
        ]);
        const saltBuffer = Buffer.from(salt, Encoding.UTF8);
        const info = Buffer.from(CRYPTO.HKDF_INFO_MESSAGE, Encoding.UTF8);
        const keyLength = 32;

        const derivedKey = hkdfSync(CRYPTO.HASH_ALGORITHM, ikm, saltBuffer, info, keyLength);
        return Buffer.from(derivedKey).toString(Encoding.HEX);
    }

    public encryptAESGCM(keyHex: string, plaintext: string): { payload: string; iv: string; tag: string } {
        const iv = randomBytes(CRYPTO.IV_BYTES);
        const cipher = createCipheriv(CRYPTO.ENCRYPTION_ALGORITHM, Buffer.from(keyHex, Encoding.HEX), iv);

        let encrypted = cipher.update(plaintext, Encoding.UTF8, Encoding.HEX);
        encrypted += cipher.final(Encoding.HEX);

        const tag = cipher.getAuthTag().toString(Encoding.HEX);

        return {
            payload: encrypted,
            iv: iv.toString(Encoding.HEX),
            tag: tag
        };
    }

    public decryptAESGCM(keyHex: string, payloadHex: string, ivHex: string, tagHex: string): string {
        const decipher = createDecipheriv(
            CRYPTO.ENCRYPTION_ALGORITHM,
            Buffer.from(keyHex, Encoding.HEX),
            Buffer.from(ivHex, Encoding.HEX)
        );

        decipher.setAuthTag(Buffer.from(tagHex, Encoding.HEX));

        let decrypted = decipher.update(payloadHex, Encoding.HEX, Encoding.UTF8);
        decrypted += decipher.final(Encoding.UTF8);

        return decrypted;
    }

    private normalizeKeyToHex(input: string): string | null {
        try {
            if (/^[0-9a-fA-F]+$/.test(input)) {
                return input;
            }

            if (input.includes('-----BEGIN')) {
                const keyObj = createPublicKey(input);
                const jwk = keyObj.export({ format: 'jwk' });
                if (jwk.kty === 'EC' && (jwk.crv === 'K-256' || jwk.crv === CryptoCurve.SECP256K1)) {
                    const x = Buffer.from(jwk.x!, Encoding.BASE64URL).toString(Encoding.HEX);
                    const y = Buffer.from(jwk.y!, Encoding.BASE64URL).toString(Encoding.HEX);
                    return '04' + x.padStart(64, '0') + y.padStart(64, '0');
                }
            }

            if (/^[a-zA-Z0-9+/=]+$/.test(input)) {
                const buf = Buffer.from(input, Encoding.BASE64);
                return buf.toString(Encoding.HEX);
            }

            return null;
        } catch {
            return null;
        }
    }
}
