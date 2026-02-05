import { ProcessController } from '../../src/controllers/process.controller';
import { InfrastructureFactory } from '../../src/infrastructure/factories/infrastructure.factory';
import { FastifyRequest, FastifyReply } from 'fastify';

jest.mock('../../src/infrastructure/factories/infrastructure.factory', () => ({
    InfrastructureFactory: {
        getProcessEncryptedDataUseCase: jest.fn()
    }
}));

describe('ProcessController', () => {
    let mockReq: any;
    let mockReply: any;

    beforeEach(() => {
        jest.clearAllMocks();
        mockReq = {
            body: {
                deviceId: 'device-123',
                kid: 'kid-123',
                publicKeyEphemeral: 'enc-pem',
                encryptedData: 'enc-data'
            },
            log: {
                info: jest.fn(),
                error: jest.fn()
            },
            url: '/test'
        };
        mockReply = {
            status: jest.fn().mockReturnThis(),
            send: jest.fn().mockReturnThis()
        };
    });

    it('should handle successful process request', async () => {
        const mockUseCase = {
            execute: jest.fn().mockResolvedValue({
                kid: 'new-kid',
                publicKeyEphemeral: 'new-enc-pem',
                encryptedData: 'new-enc-data'
            })
        };
        (InfrastructureFactory.getProcessEncryptedDataUseCase as jest.Mock).mockReturnValue(mockUseCase);

        await ProcessController.handle(mockReq, mockReply);

        expect(mockReply.status).toHaveBeenCalledWith(200);
        expect(mockReply.send).toHaveBeenCalledWith(expect.objectContaining({
            kid: 'new-kid'
        }));
    });

    it('should handle errors with 500 or specified status', async () => {
        const mockUseCase = {
            execute: jest.fn().mockRejectedValue(new Error('401'))
        };
        (InfrastructureFactory.getProcessEncryptedDataUseCase as jest.Mock).mockReturnValue(mockUseCase);

        await ProcessController.handle(mockReq, mockReply);
        expect(mockReply.status).toHaveBeenCalledWith(401);
    });

    it('should return 400 if fields are missing', async () => {
        mockReq.body = {};
        await ProcessController.handle(mockReq, mockReply);
        expect(mockReply.status).toHaveBeenCalledWith(400);
    });

    it('should return 500 on unexpected error', async () => {
        const mockUseCase = {
            execute: jest.fn().mockRejectedValue(new Error('Unexpected logic error'))
        };
        (InfrastructureFactory.getProcessEncryptedDataUseCase as jest.Mock).mockReturnValue(mockUseCase);

        await ProcessController.handle(mockReq, mockReply);
        expect(mockReply.status).toHaveBeenCalledWith(500);
    });
});
