import { FastifyRequest, FastifyReply } from 'fastify';
import { ProcessRequestDTO } from '../application/dtos/process.dto';
import { InfrastructureFactory } from '../infrastructure/factories/infrastructure.factory';
import { HttpStatus, ERROR_MESSAGES } from '../config/constants';

export class ProcessController {

    static async handle(request: FastifyRequest, reply: FastifyReply) {
        const start = Date.now();
        request.log.info(`[Process] REQUEST START - url: ${request.url}`);

        try {
            const body = request.body as ProcessRequestDTO;
            const { deviceId, kid, publicKeyEphemeral, encryptedData } = body;

            if (!deviceId || !kid || !publicKeyEphemeral || !encryptedData) {
                return reply.status(HttpStatus.BAD_REQUEST).send({
                    status: HttpStatus.BAD_REQUEST,
                    body: ERROR_MESSAGES.MISSING_FIELDS
                });
            }

            const useCase = InfrastructureFactory.getProcessEncryptedDataUseCase();
            const result = await useCase.execute(body);

            const duration = Date.now() - start;
            request.log.info(`[Process] SUCCESS - Total Duration: ${duration}ms`);
            result.duration = duration;

            return reply.status(HttpStatus.OK).send(result);

        } catch (error: any) {
            request.log.error(`[Process] FAIL: ${error.message}`);

            const statusCode = error.message.includes('401')
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.INTERNAL_SERVER_ERROR;

            return reply.status(statusCode).send({
                status: statusCode,
                error: error.message.includes('401') ? ERROR_MESSAGES.UNAUTHORIZED : ERROR_MESSAGES.INTERNAL_ERROR
                // detail field removed for security
            });
        }
    }
}
