export interface IIdentityService {
    getEntropy(deviceId: string): Promise<string>;
}
