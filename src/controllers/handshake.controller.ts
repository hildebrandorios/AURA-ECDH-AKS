import { FastifyRequest, FastifyReply } from 'fastify';
import { HandshakeRequestDTO } from '../application/dtos/handshake.dto';
import { InfrastructureFactory } from '../infrastructure/factories/infrastructure.factory';
import { HttpStatus, VALIDATION } from '../config/constants';
import { STRINGS, ERROR_MESSAGES } from '../config/string-constants';

export class HandshakeController {
    static async handle(request: FastifyRequest, reply: FastifyReply) {
        const start = Date.now();
        request.log.info(`${STRINGS.LOG_HANDSHAKE_START} ${request.url}`);

        try {
            const body = request.body as HandshakeRequestDTO;
            const { deviceId, publicKeyPrimary } = body;

            if (!deviceId || !publicKeyPrimary) {
                return reply.status(HttpStatus.BAD_REQUEST).send({
                    status: HttpStatus.BAD_REQUEST,
                    body: ERROR_MESSAGES.MISSING_FIELDS
                });
            }

            if (!VALIDATION.UUID.test(deviceId)) {
                return reply.status(HttpStatus.BAD_REQUEST).send({
                    status: HttpStatus.BAD_REQUEST,
                    body: STRINGS.ERR_INVALID_UUID
                });
            }

            const isPem = publicKeyPrimary.includes(VALIDATION.PEM_MARKER);
            const isBase64 = VALIDATION.BASE64_REGEX.test(publicKeyPrimary);
            if (publicKeyPrimary.length < VALIDATION.PUBKEY_MIN_LENGTH || (!isPem && !isBase64)) {
                return reply.status(HttpStatus.BAD_REQUEST).send({
                    status: HttpStatus.BAD_REQUEST,
                    body: STRINGS.ERR_INVALID_PUBKEY
                });
            }

            const useCase = InfrastructureFactory.getPerformHandshakeUseCase();
            const result = await useCase.execute({ deviceId, publicKeyPrimary });

            const duration = Date.now() - start;
            request.log.info(`${STRINGS.LOG_HANDSHAKE_SUCCESS} ${duration}ms`);
            result.duration = duration;

            return reply.status(HttpStatus.OK).send(result);

        } catch (error: any) {
            request.log.error(`${STRINGS.LOG_CRITICAL} ${error.message}`);
            return reply.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
                status: HttpStatus.INTERNAL_SERVER_ERROR,
                error: ERROR_MESSAGES.INTERNAL_ERROR
            });
        }
    }
}
