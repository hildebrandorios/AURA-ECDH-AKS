import { HandshakeController } from '../../src/controllers/handshake.controller';
import { InfrastructureFactory } from '../../src/infrastructure/factories/infrastructure.factory';
import { FastifyRequest, FastifyReply } from 'fastify';

// Completely mock the InfrastructureFactory
jest.mock('../../src/infrastructure/factories/infrastructure.factory', () => ({
    InfrastructureFactory: {
        getPerformHandshakeUseCase: jest.fn()
    }
}));

describe('HandshakeController', () => {
    let mockReq: any;
    let mockReply: any;

    beforeEach(() => {
        jest.clearAllMocks();
        mockReq = {
            body: {
                deviceId: '550e8400-e29b-41d4-a716-446655440000',
                publicKeyPrimary: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAabcde1234567890abcdef'
            },
            log: {
                info: jest.fn(),
                error: jest.fn()
            },
            url: '/handshake'
        };
        mockReply = {
            status: jest.fn().mockReturnThis(),
            send: jest.fn().mockReturnThis()
        };
    });

    it('should return 200 and data on successful handshake', async () => {
        const mockUseCase = {
            execute: jest.fn().mockResolvedValue({
                publicKeyPrimary: 'p-res',
                publicKeyEphemeral: 'e-res',
                kid: 'kid-res'
            })
        };
        (InfrastructureFactory.getPerformHandshakeUseCase as jest.Mock).mockReturnValue(mockUseCase);

        await HandshakeController.handle(mockReq, mockReply);

        expect(mockReply.status).toHaveBeenCalledWith(200);
        expect(mockReply.send).toHaveBeenCalledWith(expect.objectContaining({
            kid: 'kid-res'
        }));
    });

    it('should return 400 if required fields are missing', async () => {
        mockReq.body = {};
        await HandshakeController.handle(mockReq, mockReply);
        expect(mockReply.status).toHaveBeenCalledWith(400);
        expect(mockReply.send).toHaveBeenCalledWith(expect.objectContaining({
            body: expect.stringContaining('deviceId')
        }));
    });

    it('should return 500 on use case failure', async () => {
        const mockUseCase = {
            execute: jest.fn().mockRejectedValue(new Error('Use case error'))
        };
        (InfrastructureFactory.getPerformHandshakeUseCase as jest.Mock).mockReturnValue(mockUseCase);

        await HandshakeController.handle(mockReq, mockReply);

        expect(mockReply.status).toHaveBeenCalledWith(500);
        expect(mockReply.send).toHaveBeenCalledWith(expect.objectContaining({
            error: "Internal Server Error",
            status: 500
        }));
    });
});
