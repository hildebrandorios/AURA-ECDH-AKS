import { httpTriggerHandsheck } from '../handshake.function';
import { HttpRequest, InvocationContext } from "@azure/functions";
import { PerformHandshake } from "../../application/use-cases/perform-handshake.use-case";

// Mock uuid validation
jest.mock('uuid', () => ({
    validate: jest.fn(),
    version: jest.fn()
}));

// Mock the Use Case
jest.mock("../../application/use-cases/perform-handshake.use-case");

import { validate as uuidValidate, version as uuidVersion } from 'uuid';

describe('httpTriggerHandsheck', () => {
    let mockRequest: any;
    let mockContext: any;

    beforeEach(() => {
        mockRequest = {
            json: jest.fn(),
            url: 'http://localhost/api/handshake'
        };
        mockContext = {
            log: jest.fn(),
            error: jest.fn(),
            warn: jest.fn(),
        } as unknown as InvocationContext;

        (uuidValidate as jest.Mock).mockReturnValue(true);
        (uuidVersion as jest.Mock).mockReturnValue(5);
    });

    it('should return 200 and keys on valid request', async () => {
        const mockResult = {
            publicKeyPrimary: 'pem-prim',
            publicKeyEphemeral: 'pem-eph',
            kid: 'mock-kid'
        };

        // Mock UseCase execution
        (PerformHandshake.prototype.execute as jest.Mock).mockResolvedValue(mockResult);

        mockRequest.json.mockResolvedValue({
            deviceId: 'valid-v5-uuid',
            publicKeyPrimary: 'valid-key'
        });

        const response = await httpTriggerHandsheck(mockRequest as HttpRequest, mockContext);

        expect(response.status).toBe(200);
        expect(response.jsonBody).toEqual(mockResult);
    });

    it('should return 400 on missing fields', async () => {
        mockRequest.json.mockResolvedValue({ deviceId: 'only' });
        const response = await httpTriggerHandsheck(mockRequest as HttpRequest, mockContext);
        expect(response.status).toBe(400);
    });

    it('should return 500 on use case failure', async () => {
        (PerformHandshake.prototype.execute as jest.Mock).mockRejectedValue(new Error("Logic error"));
        mockRequest.json.mockResolvedValue({
            deviceId: 'valid-v5-uuid',
            publicKeyPrimary: 'valid-key'
        });

        const response = await httpTriggerHandsheck(mockRequest as HttpRequest, mockContext);
        expect(response.status).toBe(500);
    });
});
