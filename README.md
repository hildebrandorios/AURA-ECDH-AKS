# Azure Encryption Service - Proyecto de Comunicación Segura

Este proyecto implementa un protocolo de comunicación cifrada bidireccional de alta seguridad utilizando **Elliptic Curve Diffie-Hellman (ECDH)** para el intercambio de llaves y **AES-256-GCM** para el cifrado de mensajes, utilizando **Redis** para la gestión de sesiones.

## 🚀 Inicio Rápido

### Requisitos Previos
- Node.js v20+
- Instancia de Redis (Local o Azure Cache for Redis)

### Instalación
```bash
npm install
```

### Ejecutar Localmente
Para ejecutar el servidor en modo desarrollo o producción localmente:

```bash
# Modo Desarrollo (con recarga automática)
npm run dev

# Modo Producción
npm run build
npm start
```

## ⚙️ Configuración (.env)

El sistema requiere las siguientes variables de entorno configuradas en un archivo `.env` en la raíz del proyecto para funcionar correctamente.

| Variable | Descripción | Ejemplo / Notas |
|----------|-------------|-----------------|
| `PORT` | Puerto donde escuchará el servidor | `3000` |
| `ECC_PRIVATE_KEY` | Clave Privada ECC (Hex/PEM) para Entropía | `04af...` o Contenido PEM |
| `RSA_PRIVATE_KEY` | Ruta al archivo `.pem` o contenido de la clave privada | `./keys/rsa.key` o `-----BEGIN...` |
| `REDIS_CONNECTION_STRING` | Cadena de conexión a Redis | `redis://:pass@host:6379` |


> **Nota sobre `RSA_PRIVATE_KEY`**: Para entornos de producción (Docker/K8s), se recomienda montar la clave como un archivo (Secret) y apuntar esta variable a la ruta del archivo (ej: `/app/keys/private.key`).

## 🐳 Despliegue con Docker y Kubernetes

Consulte [DEPLOYMENT.md](DEPLOYMENT.md) para instrucciones detalladas.

### Docker Build & Run

```bash
# Construir la imagen
docker build -t pragmaregistry.azurecr.io/aura-ecdh:v1 .

# Ejecutar contenedor (ejemplo con env file)
docker run -p 3000:3000 --env-file .env pragmaregistry.azurecr.io/aura-ecdh:v1
```

---

## 🛠️ Herramientas de Prueba y Validación

He incluido dos scripts principales en la carpeta `scripts/` para validar el sistema:

### 1. Demostración End-to-End (`e2e-demo.ts`)
Valida el flujo completo: Handshake -> Derivación de Llaves -> Envío de Mensaje Cifrado -> Descifrado de Respuesta.

**Ejecución:**
```bash
npx tsx scripts/e2e-demo.ts
```

### 2. Herramientas de Performance (`performance-test.ts`)
Simula carga real con múltiples usuarios concurrentes y reporta métricas avanzadas.

**Ejecución:**
```bash
# Simular 10 usuarios, 100 peticiones en 10 segundos
npx tsx scripts/performance-test.ts --users 10 --requests 100 --seconds 10
```

---

## 🏗️ Arquitectura y Seguridad

El sistema sigue los principios de **Arquitectura Limpia (Clean Architecture)**:

- **Protocolo de Seguridad**:
    - **ECDH (secp256k1)**: Intercambio de llaves seguro.
    - **SHA256 KDF**: Derivación de llaves de mensaje ($K_m$).
    - **Rotación Dinámica**: Cada mensaje genera un nuevo `KID` y una nueva llave efímera del servidor.
    - **Formato Optimizado**: Mensajes en `Base64(IV + Tag + Payload)` para minimizar el tamaño del JSON.
- **Infraestructura**:
    - **Local Key Adapter**: Gestión de identidad usando llaves inyectadas.
    - **Redis**: Gestión de sesiones con TTL automático.

## 🧪 Pruebas Automatizadas
La suite de pruebas utiliza **Jest** y garantiza la integridad de los algoritmos criptográficos.

```bash
npm test
```
