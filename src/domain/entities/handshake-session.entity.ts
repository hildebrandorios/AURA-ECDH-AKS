export class HandshakeSession {
    constructor(
        public readonly deviceId: string,
        public readonly kid: string,
        public readonly sharedSecretPrimary: string,
        public readonly ephemeralPrivateKey: string
    ) { }

    public static create(deviceId: string, kid: string, sharedSecret: string, ephPriv: string): HandshakeSession {
        // Domain logic/validation could go here (DDD)
        return new HandshakeSession(deviceId, kid, sharedSecret, ephPriv);
    }
}
