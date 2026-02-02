export interface ISessionRepository {
    storePrimarySecret(deviceId: string, secret: string, ttlSeconds: number): Promise<void>;
    storeEphemeralPrivateKey(kid: string, privateKey: string, ttlSeconds: number): Promise<void>;
    storeLastKidMapping(deviceId: string, kid: string, ttlSeconds: number): Promise<void>;
    getLastKid(deviceId: string): Promise<string | null>;
    getPrimarySecret(deviceId: string): Promise<string | null>;
    getEphemeralPrivateKey(kid: string): Promise<string | null>;
    setKeyExpiry(key: string, ttlSeconds: number): Promise<void>;
}
