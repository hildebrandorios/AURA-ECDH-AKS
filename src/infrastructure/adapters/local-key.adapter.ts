import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { createPublicKey, createPrivateKey, privateDecrypt, privateEncrypt, constants } from "node:crypto";
import { CRYPTO, Encoding } from "../../config/constants";
import { STRINGS, ERROR_MESSAGES } from "../../config/string-constants";
import * as fs from 'fs';
import * as path from 'path';

const WATCHER_DEBOUNCE_MS = 200;
const PEM_BEGIN_MARKER = '-----BEGIN';

export class LocalKeyAdapter implements IIdentityService {
    private rsaPrivateKey: string | null = null;
    private rsaPublicKey: string | null = null;
    private eccPrivateKey: string | null = null;
    private eccKeyPath: string | null = null;
    private rsaKeyPath: string | null = null;

    constructor(
        private readonly eccPrivateKeyConfig: string,
        private readonly rsaPrivateKeyConfig: string
    ) { }

    public async initialize(): Promise<void> {
        await this.loadECCKey();
        await this.loadRSAKey();

        if (this.eccKeyPath) this.setupWatcher('ECC', this.eccKeyPath);
        if (this.rsaKeyPath) this.setupWatcher('RSA', this.rsaKeyPath);
    }

    private async loadECCKey(): Promise<void> {
        const { content, filePath } = this.resolveKey(this.eccPrivateKeyConfig);
        if (!content) {
            throw new Error(`${ERROR_MESSAGES.KEY_ERROR}: ${STRINGS.ERR_ECC_KEY_NOT_FOUND}`);
        }

        try {
            createPrivateKey(content);
            this.eccPrivateKey = content;
            this.eccKeyPath = filePath || null;
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.KEY_ERROR}: ${STRINGS.ERR_INVALID_ECC} - ${e.message}`);
        }
    }

    private async loadRSAKey(): Promise<void> {
        const { content, filePath } = this.resolveKey(this.rsaPrivateKeyConfig);
        if (!content) {
            throw new Error(`${ERROR_MESSAGES.KEY_ERROR}: ${STRINGS.ERR_RSA_KEY_NOT_FOUND}`);
        }

        try {
            this.rsaPublicKey = createPublicKey(content).export({ type: 'spki', format: 'pem' }) as string;
            this.rsaPrivateKey = content;
            this.rsaKeyPath = filePath || null;
        } catch (e: any) {
            throw new Error(`${ERROR_MESSAGES.KEY_ERROR}: ${STRINGS.ERR_INVALID_RSA} - ${e.message}`);
        }
    }

    private resolveKey(configValue: string): { content: string | null; filePath?: string } {
        if (!configValue) return { content: null };

        if (configValue.includes(PEM_BEGIN_MARKER)) {
            return { content: configValue.trim() };
        }

        try {
            const resolvedPath = path.resolve(process.cwd(), configValue);
            if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
                const content = fs.readFileSync(resolvedPath, 'utf-8').trim();
                return { content, filePath: resolvedPath };
            }
        } catch (e) {
            // Path resolution failed
        }

        return { content: null };
    }

    private setupWatcher(type: 'ECC' | 'RSA', filePath: string): void {
        let debounceTimer: NodeJS.Timeout | null = null;

        fs.watch(filePath, (event) => {
            if (event === 'change' || event === 'rename') {
                if (debounceTimer) clearTimeout(debounceTimer);

                debounceTimer = setTimeout(async () => {
                    try {
                        const { content } = this.resolveKey(filePath);
                        if (!content) throw new Error(STRINGS.ERR_FILE_RELOAD);

                        if (type === 'ECC') {
                            createPrivateKey(content);
                            this.eccPrivateKey = content;
                            console.log(`${STRINGS.LOG_HOT_RELOAD_ECC_SUCCESS} ${filePath}`);
                        } else {
                            const newPubKey = createPublicKey(content).export({ type: 'spki', format: 'pem' }) as string;
                            this.rsaPrivateKey = content;
                            this.rsaPublicKey = newPubKey;
                            console.log(`${STRINGS.LOG_HOT_RELOAD_RSA_SUCCESS} ${filePath}`);
                        }
                    } catch (err: any) {
                        console.error(`${STRINGS.LOG_HOT_RELOAD_FAILED} ${type} at ${filePath}: ${err.message}. ${STRINGS.LOG_HOT_RELOAD_ERROR_TAIL}`);
                    }
                }, WATCHER_DEBOUNCE_MS);
            }
        });
    }

    public getEntropy(): string {
        if (!this.eccPrivateKey) {
            throw new Error(STRINGS.ERR_IDENTITY_NOT_INIT);
        }
        return this.eccPrivateKey;
    }

    public async getRSAPublicKey(): Promise<string> {
        if (!this.rsaPublicKey) {
            throw new Error(STRINGS.ERR_RSA_PUB_NOT_AVAIL);
        }
        return this.rsaPublicKey;
    }

    public async decryptRSA(ciphertextB64: string): Promise<string> {
        if (!this.rsaPrivateKey) {
            throw new Error(STRINGS.ERR_RSA_PRIV_NOT_LOADED);
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
            throw new Error(STRINGS.ERR_RSA_PRIV_NOT_LOADED);
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
            throw new Error(`${ERROR_MESSAGES.DECRYPTION_FAILED}: ${STRINGS.ERR_AUTH_FAILED} - ${e.message}`);
        }
    }
}
