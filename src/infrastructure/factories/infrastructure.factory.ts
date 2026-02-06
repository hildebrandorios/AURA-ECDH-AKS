import { ENV_KEYS } from "../../config/constants";
import { ICryptoProvider } from "../../domain/interfaces/crypto-provider.interface";
import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { ISessionRepository } from "../../domain/interfaces/session-repository.interface";
import { NativeCryptoAdapter } from "../adapters/native-crypto.adapter";
import { LocalKeyAdapter } from "../adapters/local-key.adapter";
import { RedisSessionRepository } from "../adapters/redis-session.repository";
import { ProcessEncryptedData } from "../../application/use-cases/process-encrypted-data.use-case";
import { PerformHandshake } from "../../application/use-cases/perform-handshake.use-case";

export class InfrastructureFactory {
    private static cryptoProvider: ICryptoProvider | null = null;
    private static identityService: IIdentityService | null = null;
    private static sessionRepository: ISessionRepository | null = null;

    private static getEnv(key: string, defaultValue: string = ""): string {
        return process.env[key] || defaultValue;
    }

    public static getCryptoProvider(): ICryptoProvider {
        if (!this.cryptoProvider) {
            this.cryptoProvider = new NativeCryptoAdapter();
        }
        return this.cryptoProvider;
    }

    public static getIdentityService(): IIdentityService {
        if (!this.identityService) {
            const eccPrivateKey = this.getEnv(ENV_KEYS.ECC_PRIVATE_KEY);
            const rsaPrivateKey = this.getEnv(ENV_KEYS.RSA_PRIVATE_KEY);
            this.identityService = new LocalKeyAdapter(eccPrivateKey, rsaPrivateKey);
        }
        return this.identityService;
    }

    public static getSessionRepository(): ISessionRepository {
        if (!this.sessionRepository) {
            const connectionString = this.getEnv(ENV_KEYS.REDIS_CONNECTION);
            this.sessionRepository = new RedisSessionRepository(connectionString);
        }
        return this.sessionRepository;
    }

    public static getProcessEncryptedDataUseCase(): ProcessEncryptedData {
        return new ProcessEncryptedData(
            this.getCryptoProvider(),
            this.getSessionRepository()
        );
    }

    public static getPerformHandshakeUseCase(): PerformHandshake {
        return new PerformHandshake(
            this.getCryptoProvider(),
            this.getIdentityService(),
            this.getSessionRepository()
        );
    }
}
