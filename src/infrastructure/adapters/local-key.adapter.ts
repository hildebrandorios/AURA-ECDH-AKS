import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { createPublicKey, privateDecrypt, privateEncrypt, constants } from "node:crypto";
import { CRYPTO, Encoding, ERROR_MESSAGES } from "../../config/constants";
import * as fs from 'fs';
import * as path from 'path';

export class LocalKeyAdapter implements IIdentityService {
    private rsaPrivateKey: string | null = null;
    private rsaPublicKey: string | null = null;
    private eccPrivateKey: string | null = null;

    constructor(
        private readonly eccPrivateKeyConfig: string,
        private readonly rsaPrivateKeyConfig: string
    ) { }

    public async initialize(): Promise<void> {
        // Load ECC Private Key (Entropy)
        this.eccPrivateKey = this.resolveKey(this.eccPrivateKeyConfig);
        if (!this.eccPrivateKey) {
            throw new Error(`${ERROR_MESSAGES.KEY_ERROR}: ECC Private Key not found.`);
        }

        // Load RSA Private Key
        this.rsaPrivateKey = this.resolveKey(this.rsaPrivateKeyConfig);
        if (!this.rsaPrivateKey) {
            throw new Error(`${ERROR_MESSAGES.KEY_ERROR}: RSA Private Key not found.`);
        }

        try {
            this.rsaPublicKey = createPublicKey(this.rsaPrivateKey).export({ type: 'spki', format: 'pem' }) as string;
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.KEY_ERROR}: RSA Private Key invalid - ${e.message}`);
        }
    }

    private resolveKey(configValue: string): string | null {
        if (!configValue) return null;

        // Check if it's a file path
        if (configValue.startsWith('./') || configValue.startsWith('/') || configValue.startsWith('../')) {
            try {
                const resolvedPath = path.resolve(process.cwd(), configValue);
                if (fs.existsSync(resolvedPath)) {
                    return fs.readFileSync(resolvedPath, 'utf-8').trim();
                }
            } catch (e) {
                // Ignore file read errors, might be direct content
            }
        }

        // Return as direct content
        return configValue;
    }

    public getEntropy(): string {
        if (!this.eccPrivateKey) {
            throw new Error("IdentityService not initialized.");
        }
        return this.eccPrivateKey;
    }

    public async getRSAPublicKey(): Promise<string> {
        if (!this.rsaPublicKey) {
            throw new Error("RSA Public Key not available.");
        }
        return this.rsaPublicKey;
    }

    public async decryptRSA(ciphertextB64: string): Promise<string> {
        if (!this.rsaPrivateKey) {
            throw new Error("RSA Private Key not loaded.");
        }

        const buffer = Buffer.from(ciphertextB64, Encoding.BASE64);

        try {
            const decrypted = privateDecrypt(
                {
                    key: this.rsaPrivateKey,
                    padding: constants[CRYPTO.RSA_OAEP_PADDING],
                    oaepHash: CRYPTO.HASH_ALGORITHM
                },
                buffer
            );
            return decrypted.toString(Encoding.UTF8);
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.DECRYPTION_FAILED}: ${e.message}`);
        }
    }

    public encryptRSAPrivate(plaintext: string | Buffer): string {
        if (!this.rsaPrivateKey) {
            throw new Error("RSA Private Key not loaded.");
        }

        const buffer = typeof plaintext === 'string' ? Buffer.from(plaintext, Encoding.UTF8) : plaintext;

        try {
            const encrypted = privateEncrypt(
                {
                    key: this.rsaPrivateKey,
                    padding: constants[CRYPTO.RSA_PKCS1_PADDING]
                },
                buffer
            );
            return encrypted.toString(Encoding.BASE64);
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.DECRYPTION_FAILED}: RSA Auth failed - ${e.message}`);
        }
    }
}
