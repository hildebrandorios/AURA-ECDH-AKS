import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import { HandshakeController } from './controllers/handshake.controller';
import { ProcessController } from './controllers/process.controller';

export const createApp = async (): Promise<FastifyInstance> => {
    const app = Fastify({
        logger: true,
        connectionTimeout: 30000,
    });

    // Plugins
    const corsOrigin = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN : true;
    await app.register(cors, {
        origin: corsOrigin
    });

    // Routes
    app.post('/api/handshake', HandshakeController.handle);
    app.post('/api/process', ProcessController.handle);

    // Health Check
    app.get('/health', async () => {
        return { status: 'ok', timestamp: new Date().toISOString() };
    });

    return app;
};
