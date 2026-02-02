import { IIdentityService } from "../../domain/interfaces/identity-service.interface";
import { DefaultAzureCredential } from "@azure/identity";
import { KeyClient, CryptographyClient, KeyVaultKey } from "@azure/keyvault-keys";

export class AzureKeyVaultAdapter implements IIdentityService {
    private credential = new DefaultAzureCredential();
    private keyClient: KeyClient;
    private cryptoClient: CryptographyClient | null = null;
    private cachedKeyId: string | null = null;

    constructor(vaultUrl: string, private readonly keyName: string) {
        this.keyClient = new KeyClient(vaultUrl, this.credential);
    }

    public async getEntropy(deviceId: string): Promise<string> {
        const client = await this.getCryptoClient();
        const algorithm = "ES256K";
        const dataBuffer = Buffer.from(deviceId, 'utf-8');

        // signing with 10s timeout logic should be external or here
        const signature = await client.signData(algorithm, dataBuffer);
        return Buffer.from(signature.result).toString('hex');
    }

    private async getCryptoClient(): Promise<CryptographyClient> {
        if (this.cryptoClient) return this.cryptoClient;
        if (!this.cachedKeyId) {
            const key: KeyVaultKey = await this.keyClient.getKey(this.keyName);
            if (!key.id) throw new Error("Key ID not found");
            this.cachedKeyId = key.id;
        }
        this.cryptoClient = new CryptographyClient(this.cachedKeyId!, this.credential);
        return this.cryptoClient;
    }
}
