export interface KeyPair {
    privateKey: string;
    publicKey: string;
}

export interface ICryptoProvider {
    generateKeyPair(): KeyPair;
    deriveKeyPairFromEntropy(entropyHex: string, salt: Buffer): KeyPair;
    computeSharedSecret(privateKeyHex: string, otherPublicKeyPEM: string): string;
    validatePublicKey(publicKey: string): boolean;
    exportPublicKeyToPEM(publicKeyHex: string): string;
    encryptAESGCM(keyHex: string, plaintext: string): { payload: string; iv: string; tag: string };
    decryptAESGCM(keyHex: string, payloadHex: string, ivHex: string, tagHex: string): string;
    deriveMessageKey(primarySecretHex: string, ephemeralSecretHex: string): string;
}
