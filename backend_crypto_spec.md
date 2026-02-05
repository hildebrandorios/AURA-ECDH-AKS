# Especificación Técnica de Flujo Backend

Este documento complementa la especificación de cliente, detallando la lógica interna del backend (`src`), incluyendo la interacción con Repositorios (Redis), Proveedores de Criptografía, y Servicios de Identidad.

## Constantes del Backend
Estas constantes definen el comportamiento crítico de seguridad en el servidor.

| Constante | Valor | Descripción |
|-----------|-------|-------------|
| **Curva Primaria** | `SECP256K1` | Usada para derivar identidades persistentes desde entropía. |
| **Curva Efímera** | `X25519` | Usada para claves de sesión de un solo uso. |
| **HKDF Info** | `"HandshakeMessageKey"` | Contexto para derivación de claves de mensaje. |
| **Nonce Entropy** | `32 bytes` | Longitud del nonce para derivación primaria. |
| **TTL Sesión** | `86400s` (24h) | Tiempo de vida de la sesión activa en Redis. |
| **TTL Key Expirada**| `300s` (5m) | Tiempo de tolerancia para claves efímeras rotadas (prevención de race conditions). |

## Diagrama de Secuencia Detallado

El siguiente diagrama muestra el flujo exacto implementado en los casos de uso `PerformHandshake` y `ProcessEncryptedData`.

```mermaid
sequenceDiagram
    participant Client as Client (Device)
    participant API as API Controller
    participant UC as UseCase
    participant IS as IdentityService
    participant CP as CryptoProvider
    participant Redis as SessionRepository

    Note over Client, Redis: --- ESCENARIO A: PERFORM HANDSHAKE ---

    Client->>API: POST /handshake<br/>(deviceId, publicKeyPrimary [RSA Encrypted])
    API->>UC: execute({ deviceId, publicKeyPrimary })
    
    %% 0. RSA Decrypt
    UC->>IS: decryptRSA(publicKeyPrimary)
    IS-->>UC: Client Primary Public Key (Unencrypted)

    %% 1. Get Entropy
    UC->>IS: getEntropy()
    IS-->>UC: Server Entropy (Randomness)

    %% 2. Derive Server Primary Key
    UC->>CP: deriveKeyPairFromEntropy(entropy, nonce)
    CP-->>UC: Backend Primary Key Pair (SECP256K1)

    %% 3. Generate Server Ephemeral Key
    UC->>CP: generateKeyPair(X25519)
    CP-->>UC: Backend Ephemeral Key Pair

    %% 4. Compute Shared Secret Primary (SS_p)
    Note right of UC: SS_p = ECDH(ServerPrivPrimary, ClientPubPrimary)
    UC->>CP: computeSharedSecret(PrivP, PubP, SECP256K1)
    CP-->>UC: sharedSecretPrimary (SS_p)

    %% 5. Store Session
    Note right of Redis: Store: deviceId -> SS_p<br/>Store: kid -> ServerPrivEphemeral
    UC->>Redis: storePrimarySecret(deviceId, SS_p)<br/>storeEphemeralPrivateKey(kid, PrivE)<br/>storeLastKidMapping(deviceId, kid)

    %% Response Preparation
    UC->>IS: encryptRSAPrivate(BackendPubPrimary)
    UC->>IS: encryptRSAPrivate(BackendPubEphemeral)
    
    UC-->>API: { publicKeyPrimary, publicKeyEphemeral, kid }
    API-->>Client: 200 OK (Auth Keys)

    Note over Client, Redis: --- ESCENARIO B: PROCESS ENCRYPTED DATA ---

    Client->>API: POST /process<br/>(deviceId, kid, pubKeyEph [Enc], data [Enc])
    API->>UC: execute(payload)

    %% 1. Recovery
    UC->>Redis: getPrimarySecret(deviceId) -> SS_p
    UC->>Redis: getEphemeralPrivateKey(kid) -> ServerPrivE (Old)
    Redis-->>UC: SS_p, ServerPrivE

    %% 2. Decrypt Client Ephemeral Public Key
    Note right of UC: Decrypt Client's fresh Eph Key using SS_p
    UC->>CP: decryptAESGCM(key=SS_p, ciphertext=pubKeyEph)
    CP-->>UC: ClientPubEph (Hex)

    %% 3. Compute Ephemeral Shared Secret (SS_e)
    Note right of UC: SS_e = ECDH(ServerPrivE, ClientPubEph)
    UC->>CP: computeSharedSecret(ServerPrivE, ClientPubEph, X25519)
    CP-->>UC: SS_e

    %% 4. Derive Message Key (K_m)
    Note right of UC: K_m = HKDF(SS_p + SS_e + deviceId)
    UC->>CP: deriveMessageKey(SS_p, SS_e, deviceId)
    CP-->>UC: Message Key (K_m)

    %% 5. Decrypt Payload
    UC->>CP: decryptAESGCM(key=K_m, ciphertext=data)
    CP-->>UC: Plaintext JSON (Business Data)

    Note right of UC: ** Lógica de Negocio Aquí **<br/>(e.g. agregar timestamp)

    %% ROTACIÓN DE LLAVES (Key Rotation)
    Note right of UC: --- PREPARAR SIGUIENTE TURNO ---
    UC->>CP: generateKeyPair(X25519) -> NEXT ServerPairE

    %% Estructura de Storage para el siguiente request
    UC->>Redis: Expire OLD kid
    UC->>Redis: Store NEXT kid -> NEXT ServerPrivE
    
    %% 6. Encrypt Response
    UC->>CP: encryptAESGCM(key=K_m, plaintext=ResponseData)
    CP-->>UC: EncryptedResponse

    %% 7. Encrypt Next Server Key
    Note right of UC: Encrypt NEXT Server Pub Key with SS_p
    UC->>CP: encryptAESGCM(key=SS_p, plaintext=NEXT ServerPubE)
    CP-->>UC: EncryptedNextPubKey

    UC-->>API: { encryptedData, publicKeyEphemeral (Next), kid (Next) }
    API-->>Client: 200 OK (Response + New Keys)
```

## Detalles de Lógica Interna

### 1. Modelo Híbrido de Llaves
*   **Primary Key (Identidad)**: Se utiliza `SECP256K1`. En el backend, esta llave no es estática en disco, sino que se deriva dinámicamente usando una entropía maestra (`IdentityService.getEntropy()`) y un nonce aleatorio. Esto permite que el servidor regenere sus claves si es necesario, pero manteniendo unicidad por sesión.
*   **Ephemeral Key (Forward Secrecy)**: Se utiliza `X25519`. Se genera un nuevo par `(PrivE, PubE)` para cada handshake y para cada respuesta subsecuente (rotación continua).

### 2. Derivación de Llave de Mensaje (K_m)
Para asegurar que los mensajes estén autenticados tanto por la identidad de largo plazo como por la sesión efímera, la llave de cifrado `K_m` se deriva combinando ambos secretos:

> **K_m = HKDF( Salt=deviceId, IKM=(SS_p || SS_e), Info="HandshakeMessageKey" )**

Donde:
*   `SS_p` (Shared Secret Primary): Resultado de `ECDH(ServerPrivPrimary, ClientPubPrimary)`. Persiste en Redis por la duración de la sesión.
*   `SS_e` (Shared Secret Ephemeral): Resultado de `ECDH(ServerPrivEphemeral, ClientPubEphemeral)`. Cambia con cada mensaje.

### 3. Mecanismo de Rotación (Ratchet Simplificado)
Para garantizar *Perfect Forward Secrecy* (PFS):
1.  En cada respuesta `/process`, el servidor genera inmediatamente un **nuevo par efímero** y un **nuevo KID**.
2.  La clave privada efímera vieja asociada al request actual se marca con un TTL corto (`EXPIRED_KEY_SECONDS = 300s`) para permitir reintentos breves en caso de fallos de red, pero se descarta rápidamente.
3.  El cliente **debe** actualizar su estado con el nuevo `publicKeyEphemeral` y `kid` recibidos para poder enviar el siguiente mensaje.

### 4. Seguridad de Tránsito
*   **Handshake**: Las claves públicas del servidor viajan cifradas con RSA (clave privada del servidor, verificable por el cliente con la pública del servidor) o RSA Encryption dependiendo de la dirección.
*   **Process**:
    *   La clave pública efímera del cliente (`publicKeyEphemeral`) viaja cifrada con AES-GCM usando el secreto primario `SS_p`. Esto autentica que quien envía la clave efímera posee la identidad primaria correcta.
    *   La nueva clave pública efímera del servidor (en la respuesta) también viaja cifrada con `SS_p`.
