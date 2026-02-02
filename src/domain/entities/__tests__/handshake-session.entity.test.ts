import { HandshakeSession } from '../handshake-session.entity';

describe('HandshakeSession', () => {
    it('should create a valid session instance', () => {
        const session = HandshakeSession.create(
            'device-id',
            'kid-123',
            'shared-secret-123',
            'eph-priv-123'
        );

        expect(session.deviceId).toBe('device-id');
        expect(session.kid).toBe('kid-123');
        expect(session.sharedSecretPrimary).toBe('shared-secret-123');
        expect(session.ephemeralPrivateKey).toBe('eph-priv-123');
    });
});
