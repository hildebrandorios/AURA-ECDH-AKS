import { ISessionRepository } from "../../domain/interfaces/session-repository.interface";
import { createClient, RedisClientType } from 'redis';

export class RedisSessionRepository implements ISessionRepository {
    private client: RedisClientType;

    constructor(connectionString: string) {
        this.client = createClient({ url: connectionString });
        this.client.connect().catch(console.error);
    }

    public async storePrimarySecret(deviceId: string, secret: string, ttlSeconds: number): Promise<void> {
        await this.client.set(`handshake:primary:${deviceId}`, secret, { EX: ttlSeconds });
    }

    public async storeEphemeralPrivateKey(kid: string, privateKey: string, ttlSeconds: number): Promise<void> {
        await this.client.set(`handshake:eph:${kid}`, privateKey, { EX: ttlSeconds });
    }

    public async storeLastKidMapping(deviceId: string, kid: string, ttlSeconds: number): Promise<void> {
        await this.client.set(`handshake:lastKid:${deviceId}`, kid, { EX: ttlSeconds });
    }

    public async getLastKid(deviceId: string): Promise<string | null> {
        return (await this.client.get(`handshake:lastKid:${deviceId}`)) as string | null;
    }

    public async getPrimarySecret(deviceId: string): Promise<string | null> {
        return (await this.client.get(`handshake:primary:${deviceId}`)) as string | null;
    }

    public async getEphemeralPrivateKey(kid: string): Promise<string | null> {
        return (await this.client.get(`handshake:eph:${kid}`)) as string | null;
    }

    public async setKeyExpiry(key: string, ttlSeconds: number): Promise<void> {
        await this.client.expire(key, ttlSeconds);
    }
}
