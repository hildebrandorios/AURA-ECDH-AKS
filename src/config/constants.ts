/**
 * Centralized constants for the secure communication system
 */

/**
 * Valid cryptographic curves
 */
export enum CryptoCurve {
    SECP256K1 = 'secp256k1',
    X25519 = 'x25519'
}

/**
 * Common Encoding formats
 */
export enum Encoding {
    HEX = 'hex',
    BASE64 = 'base64',
    UTF8 = 'utf8',
    BASE64URL = 'base64url'
}

/**
 * HTTP Status Codes
 */
export enum HttpStatus {
    OK = 200,
    CREATED = 201,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    INTERNAL_SERVER_ERROR = 500
}

/**
 * Cryptographic configuration constants
 */
export const CRYPTO = {
    /** Default elliptic curve */
    DEFAULT_CURVE: CryptoCurve.SECP256K1,

    /** Suffix for ephemeral curve */
    EPHEMERAL_CURVE: CryptoCurve.X25519,

    /** Symmetric encryption algorithm */
    ENCRYPTION_ALGORITHM: 'aes-256-gcm' as const,

    /** Hash algorithm for key derivation */
    HASH_ALGORITHM: 'sha256' as const,

    /** RSA Padding labels */
    RSA_OAEP_PADDING: 'RSA_PKCS1_OAEP_PADDING' as const,
    RSA_PKCS1_PADDING: 'RSA_PKCS1_PADDING' as const,

    /** HKDF Info string */
    HKDF_INFO_MESSAGE: 'HandshakeMessageKey' as const,

    /** Nonce/salt byte length */
    NONCE_BYTES: 32,

    /** AES lengths */
    IV_BYTES: 12,
    TAG_BYTES: 16,
} as const;


/**
 * Time-to-live (TTL) constants in seconds
 */
export const TTL = {
    /** Session TTL: 24 hours */
    SESSION_SECONDS: 24 * 60 * 60,

    /** Expired ephemeral key TTL: 5 minutes */
    EXPIRED_KEY_SECONDS: 300,
} as const;

/**
 * Redis key prefixes
 */
export const REDIS_KEYS = {
    PRIMARY_PREFIX: 'handshake:primary:' as const,
    EPHEMERAL_PREFIX: 'handshake:eph:' as const,
    LAST_KID_PREFIX: 'handshake:lastKid:' as const,
} as const;

/**
 * Environment variable keys
 */
export const ENV_KEYS = {
    ECC_PRIVATE_KEY: 'ECC_PRIVATE_KEY' as const, // Changed from ECC_PUBLIC_KEY
    RSA_PRIVATE_KEY: 'RSA_PRIVATE_KEY' as const,
    REDIS_CONNECTION: 'REDIS_CONNECTION_STRING' as const,
    PORT: 'PORT' as const,
    BASE_URL: 'BASE_URL' as const,
} as const;

/**
 * Common regex and validation limits
 */
export const VALIDATION = {
    UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    PUBKEY_MIN_LENGTH: 50,
    BASE64_REGEX: /^[A-Za-z0-9+/=]+$/,
    PEM_MARKER: '-----BEGIN'
} as const;

/**
 * Server Configuration
 */
export const SERVER_CONFIG = {
    DEFAULT_PORT: 3000,
    CONNECTION_TIMEOUT: 30000,
    WATCHER_DEBOUNCE_MS: 200,
} as const;
