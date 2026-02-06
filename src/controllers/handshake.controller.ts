import { FastifyRequest, FastifyReply } from 'fastify';
import { HandshakeRequestDTO } from '../application/dtos/handshake.dto';
import { InfrastructureFactory } from '../infrastructure/factories/infrastructure.factory';
import { HttpStatus, ERROR_MESSAGES } from '../config/constants';

export class HandshakeController {

    static async handle(request: FastifyRequest, reply: FastifyReply) {
        const start = Date.now();
        request.log.info(`[Handshake] REQUEST START - url: ${request.url}`);

        try {
            const body = request.body as HandshakeRequestDTO;
            const { deviceId, publicKeyPrimary } = body;

            if (!deviceId || !publicKeyPrimary) {
                return reply.status(HttpStatus.BAD_REQUEST).send({
                    status: HttpStatus.BAD_REQUEST,
                    body: ERROR_MESSAGES.MISSING_FIELDS
                });
            }

            // Input Validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(deviceId)) {
                return reply.status(HttpStatus.BAD_REQUEST).send({
                    status: HttpStatus.BAD_REQUEST,
                    body: "Invalid deviceId format. Must be UUID."
                });
            }

            if (publicKeyPrimary.length < 50 || (!publicKeyPrimary.includes('-----BEGIN') && !/^[A-Za-z0-9+/=]+$/.test(publicKeyPrimary))) {
                return reply.status(HttpStatus.BAD_REQUEST).send({
                    status: HttpStatus.BAD_REQUEST,
                    body: "Invalid publicKeyPrimary format."
                });
            }

            const useCase = InfrastructureFactory.getPerformHandshakeUseCase();
            const result = await useCase.execute({ deviceId, publicKeyPrimary });

            const duration = Date.now() - start;
            request.log.info(`[Handshake] SUCCESS - Total Duration: ${duration}ms`);
            result.duration = duration;

            return reply.status(HttpStatus.OK).send(result);

        } catch (error) {
            request.log.error(`[Handshake] CRITICAL ERROR: ${(error as Error).message}`);
            // Security: Return generic error to client, but log full details
            return reply.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
                status: HttpStatus.INTERNAL_SERVER_ERROR,
                error: ERROR_MESSAGES.INTERNAL_ERROR
            });
        }
    }
}
