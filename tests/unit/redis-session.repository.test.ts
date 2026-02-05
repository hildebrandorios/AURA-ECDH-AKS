import { RedisSessionRepository } from '../../src/infrastructure/adapters/redis-session.repository';
import { createClient } from 'redis';

jest.mock('redis', () => ({
    createClient: jest.fn().mockReturnValue({
        connect: jest.fn().mockResolvedValue(undefined),
        on: jest.fn(),
        set: jest.fn(),
        get: jest.fn(),
        expire: jest.fn()
    })
}));

describe('RedisSessionRepository', () => {
    let repository: RedisSessionRepository;
    let mockClient: any;

    beforeEach(() => {
        mockClient = createClient();
        repository = new RedisSessionRepository('redis://localhost:6379');
    });

    it('should store primary secret', async () => {
        await repository.storePrimarySecret('device', 'secret', 100);
        expect(mockClient.set).toHaveBeenCalledWith('handshake:primary:device', 'secret', { EX: 100 });
    });

    it('should store ephemeral private key', async () => {
        await repository.storeEphemeralPrivateKey('kid', 'priv', 100);
        expect(mockClient.set).toHaveBeenCalledWith('handshake:eph:kid', 'priv', { EX: 100 });
    });

    it('should store last KID mapping', async () => {
        await repository.storeLastKidMapping('device', 'kid', 100);
        expect(mockClient.set).toHaveBeenCalledWith('handshake:lastKid:device', 'kid', { EX: 100 });
    });

    it('should get last KID', async () => {
        mockClient.get.mockResolvedValue('some-kid');
        const kid = await repository.getLastKid('device');
        expect(kid).toBe('some-kid');
    });

    it('should set key expiry', async () => {
        await repository.setKeyExpiry('key', 100);
        expect(mockClient.expire).toHaveBeenCalledWith('key', 100);
    });

    it('should get primary secret', async () => {
        mockClient.get.mockResolvedValueOnce('secret');
        const result = await repository.getPrimarySecret('id');
        expect(result).toBe('secret');
        expect(mockClient.get).toHaveBeenCalledWith('handshake:primary:id');
    });

    it('should get ephemeral private key', async () => {
        mockClient.get.mockResolvedValueOnce('priv');
        const result = await repository.getEphemeralPrivateKey('kid');
        expect(result).toBe('priv');
        expect(mockClient.get).toHaveBeenCalledWith('handshake:eph:kid');
    });
});
