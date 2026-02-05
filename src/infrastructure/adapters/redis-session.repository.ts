import { ISessionRepository } from "../../domain/interfaces/session-repository.interface";
import { createClient, RedisClientType } from 'redis';
import { REDIS_KEYS } from "../../config/constants";

export class RedisSessionRepository implements ISessionRepository {
    private client: RedisClientType;

    constructor(connectionString: string) {
        this.client = createClient({ url: connectionString });
        this.client.connect().catch(console.error);
    }

    public async storePrimarySecret(deviceId: string, secret: string, ttlSeconds: number): Promise<void> {
        await this.client.set(`${REDIS_KEYS.PRIMARY_PREFIX}${deviceId}`, secret, { EX: ttlSeconds });
    }

    public async storeEphemeralPrivateKey(kid: string, privateKey: string, ttlSeconds: number): Promise<void> {
        await this.client.set(`${REDIS_KEYS.EPHEMERAL_PREFIX}${kid}`, privateKey, { EX: ttlSeconds });
    }

    public async storeLastKidMapping(deviceId: string, kid: string, ttlSeconds: number): Promise<void> {
        await this.client.set(`${REDIS_KEYS.LAST_KID_PREFIX}${deviceId}`, kid, { EX: ttlSeconds });
    }

    public async getLastKid(deviceId: string): Promise<string | null> {
        return (await this.client.get(`${REDIS_KEYS.LAST_KID_PREFIX}${deviceId}`)) as string | null;
    }

    public async getPrimarySecret(deviceId: string): Promise<string | null> {
        return (await this.client.get(`${REDIS_KEYS.PRIMARY_PREFIX}${deviceId}`)) as string | null;
    }

    public async getEphemeralPrivateKey(kid: string): Promise<string | null> {
        return (await this.client.get(`${REDIS_KEYS.EPHEMERAL_PREFIX}${kid}`)) as string | null;
    }

    public async setKeyExpiry(key: string, ttlSeconds: number): Promise<void> {
        await this.client.expire(key, ttlSeconds);
    }
}
