# Azure Encryption Service - Proyecto de Comunicación Segura

Este proyecto implementa un protocolo de comunicación cifrada bidireccional de alta seguridad utilizando **Elliptic Curve Diffie-Hellman (ECDH)** para el intercambio de llaves y **AES-256-GCM** para el cifrado de mensajes, integrado con **Azure Key Vault** y **Redis**.

## 🚀 Inicio Rápido

### Requisitos Previos
- Node.js v20+
- Azure Functions Core Tools
- Instancia de Redis (Local o Azure Cache for Redis)
- Azure Key Vault configurado

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
| `AKV_VAULT_URL` | URL del Azure Key Vault | `https://mi-vault.vault.azure.net` |
| `AKV_MASTER_KEY_NAME` | Nombre de la clave maestra (ECC) en KV | `master-ecc` |
| `AKV_RSA_KEY_NAME` | (Opcional) Nombre de la clave RSA en KV | `rsa-key` (si difiere de la maestra) |
| `RSA_PRIVATE_KEY` | Ruta al archivo `.pem` o contenido de la clave privada | `./keys/rsa.key` o `-----BEGIN...` |
| `REDIS_CONNECTION_STRING` | Cadena de conexión a Redis | `redis://:pass@host:6379` |
| `BASE_URL` | URL base pública del servicio | `https://api.midominio.com` |

> **Nota sobre `RSA_PRIVATE_KEY`**: Para entornos de producción (Docker/K8s), se recomienda montar la clave como un archivo (Secret) y apuntar esta variable a la ruta del archivo (ej: `/app/keys/private.key`).

## 🐳 Despliegue con Docker y Kubernetes

### Docker Build & Run

```bash
# Construir la imagen (multi-platform si es necesario)
docker build -t pragmaregistry.azurecr.io/aura-ecdh:v1 .

# Ejecutar contenedor (ejemplo con env file)
docker run -p 3000:3000 --env-file .env pragmaregistry.azurecr.io/aura-ecdh:v1
```

### Despliegue en AKS (Kubernetes)

El repositorio incluye manifiestos en la carpeta `k8s/` para desplegar en Azure Kubernetes Service.

1. **Crear ConfigMap**:
```bash
kubectl create configmap app-config \
  --from-literal=vault-url="https://<TU-VAULT>.vault.azure.net" \
  --from-literal=master-key-name="master-ecc" \
  --dry-run=client -o yaml | kubectl apply -f -
```

2. **Crear Secretos (Redis & RSA)**:
```bash
# Secreto para Redis
kubectl create secret generic app-secrets \
  --from-literal=redis-connection="redis://..." \
  --dry-run=client -o yaml | kubectl apply -f -

# Secreto para Clave RSA (desde archivo)
kubectl create secret generic app-rsa-key \
  --from-file=private-key=./rsa.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

3. **Aplicar Despliegue**:
```bash
kubectl apply -f k8s/deployment.yaml

# Reiniciar pods si cambian configuraciones
kubectl rollout restart deployment aura-ecdh
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

**Métricas Incluidas:**
- **Network**: Latencia mínima, máxima y promedio por endpoint (Handshake vs Process).
- **Client Side (Front)**: Tiempo de generación de llaves, cifrado y descifrado en el dispositivo.
- **Resources**: Consumo de CPU y pico de memoria RAM durante la prueba.
- **Reliability**: Tasa de éxito/error y log detallado de fallos en `performance_errors.log`.

---

## 🏗️ Arquitectura y Seguridad

El sistema sigue los principios de **Arquitectura Limpia (Clean Architecture)**:

- **Protocolo de Seguridad**:
    - **ECDH (secp256k1)**: Intercambio de llaves seguro.
    - **SHA256 KDF**: Derivación de llaves de mensaje ($K_m$).
    - **Rotación Dinámica**: Cada mensaje genera un nuevo `KID` y una nueva llave efímera del servidor.
    - **Formato Optimizado**: Mensajes en `Base64(IV + Tag + Payload)` para minimizar el tamaño del JSON.
- **Infraestructura**:
    - **Azure Key Vault**: Almacenamiento de la entropía de identidad.
    - **Redis**: Gestión de sesiones con TTL automático.

## 🧪 Pruebas Automatizadas
La suite de pruebas utiliza **Jest** y garantiza la integridad de los algoritmos criptográficos.

```bash
npm test
```

*Este proyecto está diseñado para ser resiliente, escalable y cumplir con los más altos estándares de seguridad criptográfica.*
