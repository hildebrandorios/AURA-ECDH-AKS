export interface IIdentityService {
    initialize(): Promise<void>;
    getEntropy(): string;
    getRSAPublicKey(): Promise<string>;
    decryptRSA(ciphertextB64: string): Promise<string>;
    encryptRSAPrivate(plaintext: string | Buffer): string;
}
