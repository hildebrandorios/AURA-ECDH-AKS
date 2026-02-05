import { CryptoCurve } from "../../config/constants";

export interface KeyPair {
    privateKey: string;
    publicKey: string;
    publicKeyHex?: string;
    curve?: CryptoCurve;
}

export interface ICryptoProvider {
    generateKeyPair(curve?: CryptoCurve): KeyPair;
    deriveKeyPairFromEntropy(entropyHex: string, salt: Buffer): KeyPair;
    computeSharedSecret(privateKeyHex: string, otherPublicKey: string, curve?: CryptoCurve): string;
    validatePublicKey(publicKey: string, curve?: CryptoCurve): boolean;
    exportPublicKeyToPEM(publicKeyHex: string, curve?: CryptoCurve): string;
    encryptAESGCM(keyHex: string, plaintext: string): { payload: string; iv: string; tag: string };
    decryptAESGCM(keyHex: string, payloadHex: string, ivHex: string, tagHex: string): string;
    encryptRSA(publicKeyPEM: string, plaintext: string): string;
    decryptRSA(privateKeyPEM: string, ciphertextB64: string): string;
    deriveMessageKey(primarySecretHex: string, ephemeralSecretHex: string, salt: string): string;
}
