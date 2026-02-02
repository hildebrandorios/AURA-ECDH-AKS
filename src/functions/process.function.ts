import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import { InfrastructureFactory } from "../infrastructure/factories/infrastructure.factory";
import { ProcessRequestDTO } from "../application/dtos/process.dto";

export async function httpTriggerProcess(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    context.log(`HTTP trigger function processed a request for url "${request.url}"`);

    try {
        const body = (await request.json()) as ProcessRequestDTO;

        // Basic Validation
        if (!body.deviceId || !body.kid || !body.publicKeyEphemeral || !body.encryptedData) {
            return {
                status: 400,
                body: "Missing required fields"
            };
        }

        const useCase = InfrastructureFactory.getProcessEncryptedDataUseCase();
        const result = await useCase.execute(body);

        return {
            status: 200,
            jsonBody: result
        };

    } catch (error: any) {
        context.error(`Error in httpTriggerProcess: ${error.message}`);

        if (error.message.includes("401")) {
            return {
                status: 401,
                body: "Unauthorized: Invalid session or device"
            };
        }

        return {
            status: 500,
            body: `Internal Server Error: ${error.message}`
        };
    }
}

app.http('httpTriggerProcess', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: httpTriggerProcess
});
