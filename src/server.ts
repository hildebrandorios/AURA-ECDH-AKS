import 'dotenv/config';
import { createApp } from './app';
import { InfrastructureFactory } from './infrastructure/factories/infrastructure.factory';
import { ENV_KEYS } from './config/constants';
import { STRINGS } from './config/string-constants';

const start = async () => {
    try {
        const app = await createApp();
        const portStr = process.env[ENV_KEYS.PORT];
        const port = portStr ? parseInt(portStr) : 3000;

        const identityService = InfrastructureFactory.getIdentityService();
        await identityService.initialize();
        app.log.info(STRINGS.LOG_IDENTITY_INIT);

        await app.listen({ port, host: '0.0.0.0' });
        console.log(`${STRINGS.LOG_SERVER_LISTENING} ${port}`);

        const signals = ['SIGINT', 'SIGTERM'] as const;
        signals.forEach((signal) => {
            process.on(signal, async () => {
                await app.close();
                process.exit(0);
            });
        });
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();
