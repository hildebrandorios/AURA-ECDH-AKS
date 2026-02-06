export interface HandshakeRequestDTO {
    deviceId: string; // Plain Text
    publicKeyPrimary: string; // RSA Encrypted Base64 (Server Public Key)
}

export interface HandshakeResponseDTO {
    duration: number;
    publicKeyPrimary: string; // RSA Encrypted Base64 (Server Private Key) - DER/HEX format inside
    publicKeyEphemeral: string; // RSA Encrypted Base64 (Server Private Key) - DER/HEX format inside
    kid: string;
}
