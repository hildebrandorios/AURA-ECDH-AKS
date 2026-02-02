import { ICryptoProvider } from "../../domain/interfaces/crypto-provider.interface";
import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { ISessionRepository } from "../../domain/interfaces/session-repository.interface";
import { EllipticCryptoAdapter } from "../adapters/elliptic-crypto.adapter";
import { AzureKeyVaultAdapter } from "../adapters/key-vault.adapter";
import { RedisSessionRepository } from "../adapters/redis-session.repository";
import { ProcessEncryptedData } from "../../application/use-cases/process-encrypted-data.use-case";

export class InfrastructureFactory {
    private static cryptoProvider: ICryptoProvider | null = null;
    private static identityService: IIdentityService | null = null;
    private static sessionRepository: ISessionRepository | null = null;

    public static getCryptoProvider(): ICryptoProvider {
        if (!this.cryptoProvider) {
            this.cryptoProvider = new EllipticCryptoAdapter();
        }
        return this.cryptoProvider;
    }

    public static getIdentityService(): IIdentityService {
        if (!this.identityService) {
            const vaultUrl = process.env.AKV_VAULT_URL || "";
            const keyName = process.env.AKV_MASTER_KEY_NAME || "";
            this.identityService = new AzureKeyVaultAdapter(vaultUrl, keyName);
        }
        return this.identityService;
    }

    public static getSessionRepository(): ISessionRepository {
        if (!this.sessionRepository) {
            const connectionString = process.env.REDIS_CONNECTION_STRING || "";
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
}
