export interface ProcessRequestDTO {
    deviceId: string;
    kid: string;
    publicKeyEphemeral: string; // Base64(iv + tag + payload)
    encryptedData: string;      // Base64(iv + tag + payload)
}

export interface ProcessResponseDTO {
    duration: number;
    encryptedData: string;      // Base64(iv + tag + payload)
    publicKeyEphemeral: string; // Base64(iv + tag + payload)
    kid: string;
}
