/**
 * Centralized constants for the secure communication system
 */

/**
 * Cryptographic configuration constants
 */
export const CRYPTO = {
    /** Elliptic curve used for ECDH key exchange */
    CURVE: 'secp256k1' as const,

    /** Symmetric encryption algorithm */
    ENCRYPTION_ALGORITHM: 'aes-256-gcm' as const,

    /** Hash algorithm for key derivation */
    HASH_ALGORITHM: 'sha256' as const,

    /** Azure Key Vault signature algorithm */
    SIGNATURE_ALGORITHM: 'ES256K' as const,

    /** JWK key type for elliptic curve */
    KEY_TYPE: 'EC' as const,

    /** Alternative curve name used in some contexts */
    CURVE_ALT: 'K-256' as const,

    /** Nonce/salt byte length for key derivation */
    NONCE_BYTES: 32,

    /** Initialization vector byte length for AES-GCM */
    IV_BYTES: 12,

    /** Authentication tag byte length for AES-GCM */
    TAG_BYTES: 16,

    /** Hex string padding length */
    HEX_PADDING: 64,
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
 * Redis key prefixes for session storage
 */
export const REDIS_KEYS = {
    /** Primary shared secret prefix */
    PRIMARY_PREFIX: 'handshake:primary:' as const,

    /** Ephemeral private key prefix */
    EPHEMERAL_PREFIX: 'handshake:eph:' as const,

    /** Last KID mapping prefix */
    LAST_KID_PREFIX: 'handshake:lastKid:' as const,
} as const;

/**
 * Environment variable keys
 */
export const ENV_KEYS = {
    /** Azure Key Vault URL */
    VAULT_URL: 'AKV_VAULT_URL' as const,

    /** Azure Key Vault master key name */
    MASTER_KEY_NAME: 'AKV_MASTER_KEY_NAME' as const,

    /** Redis connection string */
    REDIS_CONNECTION: 'REDIS_CONNECTION_STRING' as const,
} as const;
