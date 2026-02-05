import { createApp } from '../../src/app';
import { InfrastructureFactory } from '../../src/infrastructure/factories/infrastructure.factory';

jest.mock('../../src/infrastructure/factories/infrastructure.factory');

describe('App Integration', () => {
    let app: any;

    beforeAll(async () => {
        app = await createApp();
    });

    afterAll(async () => {
        await app.close();
    });

    it('should respond to health check', async () => {
        const response = await app.inject({
            method: 'GET',
            url: '/health'
        });
        expect(response.statusCode).toBe(200);
        expect(response.json()).toHaveProperty('status', 'ok');
    });
});
