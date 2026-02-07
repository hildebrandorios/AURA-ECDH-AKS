import 'dotenv/config';
import { createApp } from './app';
import { InfrastructureFactory } from './infrastructure/factories/infrastructure.factory';
import { ENV_KEYS, SERVER_CONFIG } from './config/constants';
import { STRINGS } from './config/string-constants';

const start = async () => {
    try {
        const app = await createApp();
        const portStr = process.env[ENV_KEYS.PORT];
        const port = portStr ? parseInt(portStr) : SERVER_CONFIG.DEFAULT_PORT;

        const identityService = InfrastructureFactory.getIdentityService();
        await identityService.initialize();
        app.log.info(STRINGS.LOG_IDENTITY_INIT);

        await app.listen({ port, host: SERVER_CONFIG.HOST });
        console.log(`${STRINGS.LOG_SERVER_LISTENING} ${port}`);

        SERVER_CONFIG.SHUTDOWN_SIGNALS.forEach((signal) => {
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
