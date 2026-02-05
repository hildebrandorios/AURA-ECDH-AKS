# Guía de Pruebas de Carga y Rendimiento

Este documento detalla el funcionamiento de la herramienta de estrés situada en `scripts/performance-test.ts`.

## 🎯 Objetivo
Validar el comportamiento del protocolo bajo condiciones de alta concurrencia, midiendo tanto la respuesta del servidor como el impacto en los recursos del cliente.

## ⚙️ Configuración de la Prueba

El script acepta tres parámetros principales:

| Parámetro | Descripción | Defecto |
| :--- | :--- | :--- |
| `--users` | Cantidad de usuarios (dispositivos) paralelos. | 10 |
| `--requests` | Total de peticiones a realizar por usuario. | 100 |
| `--seconds` | Duración aproximada de la ráfaga de carga. | 5 |

### Ejemplo de comando:
```bash
npx tsx scripts/performance-test.ts --users 20 --requests 500 --seconds 15
```

## 🧠 Lógica de Ejecución

Para garantizar la integridad del estado en Azure (manejo de sesiones en Redis y Key Vault), el script sigue este modelo:

1.  **Paralelismo de Usuarios**: Cada usuario corre en su propio "hilo" asíncrono.
2.  **Secuencialidad de Handshake**: Cada usuario realiza entre 1 y 3 handshakes por sesión de prueba. Estos se ejecutan **uno después de otro**.
3.  **Mix de Carga**: Dentro de cada handshake exitoso:
    - Se lanza una ráfaga **paralela** de peticiones (aprovechando que el KID es válido por 5 minutos).
    - Se continúa con una cadena **secuencial** de peticiones que rotan el KID y la llave del servidor en cada paso.

## 📊 Métricas Reportadas

### 1. Latencia de Red (Network)
Se reporta Min/Avg/Max para:
- `Handshake`: Tiempo de negociación inicial.
- `Process`: Tiempo de procesamiento de datos cifrados.

### 2. Overhead Criptográfico (Client)
Mide el tiempo que el CPU del cliente dedica a:
- `KeyGen`: Generación de llaves ECDH.
- `Encrypt`: Cifrado AES-GCM local.
- `Decrypt`: Descifrado de la respuesta del servidor.

### 3. Consumo de Sistema
- `CPU Usage`: Carga porcentual total del proceso.
- `Memory Peak`: Uso máximo de RAM (RSS) registrado.

## 🔍 Diagnóstico de Errores
Si ocurren fallos, el script genera automáticamente un archivo **`performance_errors.log`** con:
- Código de estado HTTP.
- Cuerpo del mensaje de error del servidor.
- Stack trace completo del error.
- Contexto de la sesión (KID / UserID).

---
*Nota: Asegúrese de que el entorno de Azure tenga escalado suficiente para las pruebas de alta demanda.*
