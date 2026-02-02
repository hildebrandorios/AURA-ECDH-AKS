export interface HandshakeRequestDTO {
    publicKeyPrimary: string;
    deviceId: string;
}

export interface HandshakeResponseDTO {
    publicKeyPrimary: string;
    publicKeyEphemeral: string;
    kid: string;
}
