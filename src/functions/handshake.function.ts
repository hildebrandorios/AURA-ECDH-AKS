import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import { validate as uuidValidate, version as uuidVersion } from 'uuid';
import { PerformHandshake } from "../application/use-cases/perform-handshake.use-case";
import { InfrastructureFactory } from "../infrastructure/factories/infrastructure.factory";

export async function httpTriggerHandsheck(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    const start = Date.now();
    context.log(`[Handshake] REQUEST START - url: ${request.url}`);

    try {
        const body = (await request.json()) as any;
        const { publicKeyPrimary, deviceId } = body;

        // Validation
        if (!publicKeyPrimary || !deviceId) {
            return { status: 400, body: "Missing required fields" };
        }

        if (!uuidValidate(deviceId) || uuidVersion(deviceId) !== 5) {
            return { status: 400, body: "Invalid deviceId format (must be UUID v5)" };
        }

        // Wiring Application Layers
        const useCase = new PerformHandshake(
            InfrastructureFactory.getCryptoProvider(),
            InfrastructureFactory.getIdentityService(),
            InfrastructureFactory.getSessionRepository()
        );

        const result = await useCase.execute({ publicKeyPrimary, deviceId });

        const duration = Date.now() - start;
        context.log(`[Handshake] SUCCESS - Total Duration: ${duration}ms`);

        return {
            status: 200,
            jsonBody: result
        };

    } catch (error) {
        context.error(`[Handshake] CRITICAL ERROR: ${(error as Error).message}`);
        return { status: 500, body: "Internal Server Error" };
    }
}

app.http('httpTriggerHandsheck', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: httpTriggerHandsheck
});
