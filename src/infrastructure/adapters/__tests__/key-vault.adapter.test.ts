import { AzureKeyVaultAdapter } from '../key-vault.adapter';
import { KeyClient, CryptographyClient } from "@azure/keyvault-keys";

jest.mock("@azure/identity", () => ({
    DefaultAzureCredential: jest.fn()
}));

const mockGetKey = jest.fn();
const mockSignData = jest.fn();

jest.mock("@azure/keyvault-keys", () => ({
    KeyClient: jest.fn().mockImplementation(() => ({
        getKey: mockGetKey
    })),
    CryptographyClient: jest.fn().mockImplementation(() => ({
        signData: mockSignData
    }))
}));

describe('AzureKeyVaultAdapter', () => {
    let adapter: AzureKeyVaultAdapter;

    beforeEach(() => {
        jest.clearAllMocks();
        mockGetKey.mockResolvedValue({ id: 'key-id' });
        mockSignData.mockResolvedValue({ result: Buffer.from('signature') });
        adapter = new AzureKeyVaultAdapter('https://vault.url', 'key-name');
    });

    it('should return entropy and use cache', async () => {
        const entropy1 = await adapter.getEntropy('device-id');
        expect(entropy1).toBe(Buffer.from('signature').toString('hex'));
        const entropy2 = await adapter.getEntropy('device-id');
        expect(entropy2).toBe(entropy1);
        expect(mockGetKey).toHaveBeenCalledTimes(1);
    });

    it('should throw if key id is missing', async () => {
        mockGetKey.mockResolvedValueOnce({});
        const faultyAdapter = new AzureKeyVaultAdapter('https://vault.url', 'key-name');
        await expect(faultyAdapter.getEntropy('id')).rejects.toThrow("Key ID not found");
    });
});
