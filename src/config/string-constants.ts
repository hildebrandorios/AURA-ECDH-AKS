/**
 * Centralized string constants for logs and user messages
 */

export const STRINGS = {
    // Log Messages
    LOG_IDENTITY_INIT: "Identity Service initialized with Master Entropy",
    LOG_SERVER_LISTENING: "Server listening on",
    LOG_SERVER_URL: "Server listening at",
    LOG_HANDSHAKE_START: "[Handshake] REQUEST START - url:",
    LOG_HANDSHAKE_SUCCESS: "[Handshake] SUCCESS - Total Duration:",
    LOG_PROCESS_START: "[Process] REQUEST START - url:",
    LOG_PROCESS_SUCCESS: "[Process] SUCCESS - Total Duration:",
    LOG_HOT_RELOAD_ECC_SUCCESS: "[IdentityService] Hot-reload: SUCCESS - ECC key updated from",
    LOG_HOT_RELOAD_RSA_SUCCESS: "[IdentityService] Hot-reload: SUCCESS - RSA key updated from",
    LOG_HOT_RELOAD_FAILED: "[IdentityService] Hot-reload: FAILED for",
    LOG_HOT_RELOAD_ERROR_TAIL: "Keeping current key.",

    // Error Details
    ERR_ECC_KEY_NOT_FOUND: "ECC Private Key config must be valid PEM content or a file path.",
    ERR_RSA_KEY_NOT_FOUND: "RSA Private Key config must be valid PEM content or a file path.",
    ERR_INVALID_ECC: "Invalid ECC Private Key",
    ERR_INVALID_RSA: "RSA Private Key invalid",
    ERR_FILE_RELOAD: "File empty or inaccessible during reload.",
    ERR_RSA_PUB_NOT_AVAIL: "RSA Public Key not available.",
    ERR_RSA_PRIV_NOT_LOADED: "RSA Private Key not loaded.",
    ERR_IDENTITY_NOT_INIT: "IdentityService not initialized.",
    ERR_AUTH_FAILED: "RSA Auth failed",

    // Validation
    ERR_INVALID_UUID: "Invalid deviceId format. Must be UUID.",
    ERR_INVALID_PUBKEY: "Invalid publicKeyPrimary format.",
    ERR_INVALID_KID: "Invalid kid format.",
    LOG_CRITICAL: "CRITICAL ERROR:",
} as const;

export const ERROR_MESSAGES = {
    INVALID_SESSION: "401: Invalid session or device",
    MISSING_FIELDS: "Missing required fields (deviceId, publicKeyPrimary)",
    INTERNAL_ERROR: "Internal Server Error",
    UNAUTHORIZED: "Unauthorized access",
    HANDSHAKE_FAILED: "Handshake process failed",
    DECRYPTION_FAILED: "Decryption failed",
    KEY_ERROR: "Key service error",
} as const;
