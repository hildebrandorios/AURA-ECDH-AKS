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
```bash
npm run build
npm start
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
