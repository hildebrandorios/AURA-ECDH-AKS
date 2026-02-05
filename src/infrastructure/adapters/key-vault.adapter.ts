import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { DefaultAzureCredential } from "@azure/identity";
import { KeyClient, CryptographyClient } from "@azure/keyvault-keys";
import { SecretClient } from "@azure/keyvault-secrets";
import { createPublicKey, privateDecrypt, privateEncrypt, constants } from "node:crypto";
import { CRYPTO, Encoding, ERROR_MESSAGES } from "../../config/constants";

export class AzureKeyVaultAdapter implements IIdentityService {
    private credential = new DefaultAzureCredential();
    private keyClient: KeyClient;
    private secretClient: SecretClient;
    private cryptoClient: CryptographyClient | null = null;
    private cachedKeyId: string | null = null;
    private masterEntropy: string | null = null;
    private rsaPrivateKey: string | null = null;
    private rsaPublicKey: string | null = null;

    constructor(vaultUrl: string, private readonly masterKeyName: string, private readonly rsaKeyName?: string) {
        this.keyClient = new KeyClient(vaultUrl, this.credential);
        this.secretClient = new SecretClient(vaultUrl, this.credential);
    }

    public async initialize(): Promise<void> {
        if (this.masterEntropy) return;

        // 1. Inicializar Master Entropy (ECC)
        const client = await this.getEccCryptoClient(this.masterKeyName);
        const algorithm = CRYPTO.SIGNATURE_ALGORITHM;
        const dataBuffer = Buffer.from(this.masterKeyName, Encoding.UTF8);
        const signature = await client.signData(algorithm, dataBuffer);
        this.masterEntropy = Buffer.from(signature.result).toString(Encoding.HEX);

        // 2. Carga Estricta de Clave RSA Privada
        await this.loadRsaPrivateKey();
    }

    private async loadRsaPrivateKey(): Promise<void> {
        const targetRsaName = this.rsaKeyName || this.masterKeyName;

        try {
            const secret = await this.secretClient.getSecret(targetRsaName);
            if (secret.value) {
                this.rsaPrivateKey = secret.value;
            }
        } catch (e) {
            // Optional fallback log or silent fail
        }

        if (!this.rsaPrivateKey && process.env.RSA_PRIVATE_KEY) {
            this.rsaPrivateKey = process.env.RSA_PRIVATE_KEY;
        }

        if (!this.rsaPrivateKey) {
            throw new Error(`${ERROR_MESSAGES.KEY_VAULT_ERROR}: No RSA Private Key found.`);
        }

        try {
            this.rsaPublicKey = createPublicKey(this.rsaPrivateKey).export({ type: 'spki', format: 'pem' }) as string;
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.KEY_VAULT_ERROR}: RSA Private Key invalid - ${e.message}`);
        }
    }

    public getEntropy(): string {
        if (!this.masterEntropy) {
            throw new Error("IdentityService not initialized.");
        }
        return this.masterEntropy;
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

    private async getEccCryptoClient(keyName: string): Promise<CryptographyClient> {
        if (this.cryptoClient) return this.cryptoClient;

        if (!this.cachedKeyId) {
            const key = await this.keyClient.getKey(keyName);
            if (!key.id) throw new Error("ECC Key ID not found in Vault");
            this.cachedKeyId = key.id;
        }

        this.cryptoClient = new CryptographyClient(this.cachedKeyId, this.credential);
        return this.cryptoClient;
    }
}
