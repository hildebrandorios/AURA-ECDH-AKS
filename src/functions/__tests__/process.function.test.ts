import { httpTriggerProcess } from '../process.function';
import { InfrastructureFactory } from '../../infrastructure/factories/infrastructure.factory';
import { ProcessEncryptedData } from '../../application/use-cases/process-encrypted-data.use-case';

jest.mock('uuid', () => ({ v4: () => 'mock-uuid' }));
jest.mock('../../infrastructure/factories/infrastructure.factory');
jest.mock('../../application/use-cases/process-encrypted-data.use-case');

describe('httpTriggerProcess Function', () => {
    let mockContext: any;
    let mockUseCase: jest.Mocked<ProcessEncryptedData>;

    beforeEach(() => {
        mockContext = {
            log: jest.fn(),
            error: jest.fn()
        };
        mockUseCase = {
            execute: jest.fn()
        } as any;
        (InfrastructureFactory.getProcessEncryptedDataUseCase as jest.Mock).mockReturnValue(mockUseCase);
    });

    it('should return 200 on successful processing with Base64 fields', async () => {
        const mockRequest: any = {
            url: 'http://localhost/process',
            json: jest.fn().mockResolvedValue({
                deviceId: 'dev',
                kid: 'kid',
                publicKeyEphemeral: 'base64_enc_key',
                encryptedData: 'base64_enc_data'
            })
        };

        mockUseCase.execute.mockResolvedValue({
            encryptedData: 'res_b64',
            publicKeyEphemeral: 'p_res_b64',
            kid: 'new-kid'
        });

        const result = await httpTriggerProcess(mockRequest, mockContext);

        expect(result.status).toBe(200);
        expect(result.jsonBody).toEqual({
            encryptedData: 'res_b64',
            publicKeyEphemeral: 'p_res_b64',
            kid: 'new-kid'
        });
    });

    it('should return 401 on unauthorized error', async () => {
        const mockRequest: any = {
            url: 'http://localhost/process',
            json: jest.fn().mockResolvedValue({
                deviceId: 'dev',
                kid: 'kid',
                publicKeyEphemeral: 'b64',
                encryptedData: 'b64'
            })
        };

        mockUseCase.execute.mockRejectedValue(new Error('401: Unauthorized'));

        const result = await httpTriggerProcess(mockRequest, mockContext);

        expect(result.status).toBe(401);
    });

    it('should return 400 on missing fields', async () => {
        const mockRequest: any = {
            url: 'http://localhost/process',
            json: jest.fn().mockResolvedValue({})
        };

        const result = await httpTriggerProcess(mockRequest, mockContext);

        expect(result.status).toBe(400);
    });
});
