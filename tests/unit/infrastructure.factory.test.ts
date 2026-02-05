import { InfrastructureFactory } from '../../src/infrastructure/factories/infrastructure.factory';
import { NativeCryptoAdapter } from '../../src/infrastructure/adapters/native-crypto.adapter';
import { AzureKeyVaultAdapter } from '../../src/infrastructure/adapters/key-vault.adapter';
import { RedisSessionRepository } from '../../src/infrastructure/adapters/redis-session.repository';

// Mock all adapters
jest.mock('../../src/infrastructure/adapters/native-crypto.adapter');
jest.mock('../../src/infrastructure/adapters/key-vault.adapter');
jest.mock('../../src/infrastructure/adapters/redis-session.repository');

describe('InfrastructureFactory (Unit)', () => {
    const originalEnv = process.env;

    beforeEach(() => {
        jest.clearAllMocks();
        process.env = { ...originalEnv };
        process.env.AKV_VAULT_URL = 'https://test.vault.azure.net';
        process.env.AKV_MASTER_KEY_NAME = 'test-key';
        process.env.REDIS_CONNECTION_STRING = 'redis://localhost';

        // Reset singleton instances via reflection/access
        (InfrastructureFactory as any).cryptoProvider = null;
        (InfrastructureFactory as any).identityService = null;
        (InfrastructureFactory as any).sessionRepository = null;
    });

    afterAll(() => {
        process.env = originalEnv;
    });

    it('should provide a NativeCryptoAdapter and reuse the instance', () => {
        const provider1 = InfrastructureFactory.getCryptoProvider();
        const provider2 = InfrastructureFactory.getCryptoProvider();
        expect(provider1).toBeDefined();
        expect(provider1).toBe(provider2);
        expect(NativeCryptoAdapter).toHaveBeenCalledTimes(1);
    });

    it('should provide an AzureKeyVaultAdapter and reuse the instance', () => {
        const service1 = InfrastructureFactory.getIdentityService();
        const service2 = InfrastructureFactory.getIdentityService();
        expect(service1).toBeDefined();
        expect(service1).toBe(service2);
        expect(AzureKeyVaultAdapter).toHaveBeenCalledWith('https://test.vault.azure.net', 'test-key', '');
    });

    it('should provide a RedisSessionRepository and reuse the instance', () => {
        const repo1 = InfrastructureFactory.getSessionRepository();
        const repo2 = InfrastructureFactory.getSessionRepository();
        expect(repo1).toBeDefined();
        expect(repo1).toBe(repo2);
        expect(RedisSessionRepository).toHaveBeenCalledWith('redis://localhost');
    });

    it('should handle missing env vars with empty string fallbacks', () => {
        delete process.env.AKV_VAULT_URL;
        delete process.env.REDIS_CONNECTION_STRING;

        InfrastructureFactory.getIdentityService();
        InfrastructureFactory.getSessionRepository();

        expect(AzureKeyVaultAdapter).toHaveBeenCalledWith('', 'test-key', '');
        expect(RedisSessionRepository).toHaveBeenCalledWith('');
    });

    it('should provide use cases', () => {
        expect(InfrastructureFactory.getPerformHandshakeUseCase()).toBeDefined();
        expect(InfrastructureFactory.getProcessEncryptedDataUseCase()).toBeDefined();
    });
});
