# Especificación de Integración Cliente (End-to-End Encryption)

Este documento detalla el flujo criptográfico paso a paso para implementar la comunicación segura con el backend en cualquier lenguaje cliente (JavaScript/TypeScript, Swift, Kotlin, C#).

## Constantes Universales
| Parámetro | Valor | Notas |
|-----------|-------|-------|
| **Curva Primaria** | `secp256k1` | Usada para identidad persistente del dispositivo. |
| **Curva Efímera** | `X25519` | Usada para rotación de claves por sesión (Forward Secrecy). |
| **RSA Padding** | `OAEP` + `SHA256` | Para cifrado hacia el servidor. |
| **RSA Verify** | `PKCS1` | Para verificar/descifrar respuestas del handshake. |
| **AES Algo** | `AES-256-GCM` | IV=12 bytes, Tag=16 bytes. |
| **HKDF Hash** | `SHA-256` |  |
| **HKDF Info** | `"HandshakeMessageKey"` | String literal. |

## Diagrama de Secuencia de Implementación

```mermaid
sequenceDiagram
    participant Client as 📱 Cliente (Frontend)
    participant Server as ☁️ Backend (API)

    Note over Client: 🔵 FASE 1: HANDSHAKE (Inicialización)
    
    Client->>Client: 1. Generar UUID v5 (DeviceId)
    Client->>Client: 2. Generar Par Claves SECP256K1 (ClientPrimary)
    
    Note right of Client: Cifrado Asimétrico (RSA)
    Client->>Client: 3. Exportar ClientPub a Hex
    Client->>Client: 4. Cifrar ClientPub usando ServerRSA_Pub<br/>(Algo: RSA-OAEP-SHA256)
    
    Client->>Server: POST /httpTriggerHandsheck<br/>{ deviceId, publicKeyPrimary: "Base64..." }
    
    Server-->>Client: 200 OK<br/>{ kid, publicKeyPrimary, publicKeyEphemeral }
    
    Note right of Client: Validación de Servidor
    Client->>Client: 5. Descifrar publicKeyPrimary (ServerPub) usando ServerRSA_Pub<br/>(Algo: RSA-PKCS1_v1_5 / Verify)
    Client->>Client: 6. Descifrar publicKeyEphemeral (ServerEph) usando ServerRSA_Pub
    
    Note right of Client: Derivación 1
    Client->>Client: 7. ECDH(ClientPrimary_Priv, ServerPub)<br/>Output => ssP (Shared Secret Primary)
    
    Note over Client: 🟢 FASE 2: PROCESS (Envío Seguro)
    
    Client->>Client: 8. Generar Par Claves X25519 (ClientEph)
    
    Note right of Client: Protección Efímera
    Client->>Client: 9. Cifrar ClientEph_Pub usando AES-256-GCM<br/>Key: ssP, IV: Random(12)<br/>Output: Base64(IV + Tag + Cipher)
    
    Note right of Client: Derivación 2 (Forward Secrecy)
    Client->>Client: 10. ECDH(ClientEph_Priv, ServerEph)<br/>Output => ssE (Shared Secret Ephemeral)
    
    Note right of Client: Generación de Clave de Mensaje
    Client->>Client: 11. HKDF-SHA256<br/>Input: [ssP, ssE], Salt: deviceId, Info: "HandshakeMessageKey"<br/>Output => Km (32 bytes)
    
    Client->>Client: 12. Cifrar Payload JSON usando AES-256-GCM<br/>Key: Km
    
    Client->>Server: POST /httpTriggerProcess<br/>{ kid, publicKeyEphemeral, encryptedData }
    
    Server-->>Client: 200 OK<br/>{ encryptedData, ... }
    
    Client->>Client: 13. Descifrar Respuesta usando AES-256-GCM<br/>Key: Km
```

## Detalles de Implementación Técnica

### 1. Formato de Paquete Cifrado (AES-GCM)
Siempre que se cifre con AES-GCM, el resultado debe concatenarse y codificarse en **Base64** de la siguiente forma:
`Base64( IV [12 bytes]  +  AuthTag [16 bytes]  +  Ciphertext [n bytes] )`

Para descifrar:
1. Decodificar Base64 a bytes.
2. Extraer primeros 12 bytes -> **IV**.
3. Extraer siguientes 16 bytes -> **AuthTag**.
4. El resto es el **Ciphertext**.

### 2. Conversión de Claves
*   **Hex vs PEM**: El servidor suele trabajar con claves en formato Hexadecimal para ECDH. Asegúrese de convertir formatos si su librería nativa exporta en PEM o DER.
*   **X25519**: Tenga cuidado con el "endianness". Azure/Node.js suelen usar Big Endian o Raw bytes directos. 

### 3. Función HKDF
Si su lenguaje no tiene HKDF nativo, implemente el RFC 5869:
*   **Extract**: Pseudorandom Key (PRK) = HMAC-Hash(salt, IKM)
*   **Expand**: Output = HMAC-Hash(PRK, Info + 0x01)
*   **Inputs**:
    *   `IKM` (Input Key Material): Concatenación de bytes de `ssP` + `ssE`.
    *   `Salt`: Bytes del `deviceId` (UTF-8).
    *   `Info`: Cadena "HandshakeMessageKey".

---
**Nota para Desarrolladores Front-End**:
Este flujo garantiza que incluso si la clave efímera de una sesión es comprometida, las sesiones futuras (que usarán nuevas claves X25519) permanecen seguras, y la identidad del dispositivo está protegida por la clave primaria SECP256K1.
