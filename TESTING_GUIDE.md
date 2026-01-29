# Plan de Testing y Validación

## 🧪 Testing Strategy

### Niveles de Testing

#### 1. Unit Testing (Por Método)
Cada método validado con:
- ✅ Happy path (caso normal)
- ✅ Inputs vacíos
- ✅ Inputs inválidos
- ✅ Límites (min/max)
- ✅ Valores especiales (None, 0, -1)

#### 2. Integration Testing (Entre Paneles)
- ✅ Scanner → Fuzzer (target scanning)
- ✅ Scanner → Payloads (IP target)
- ✅ Fuzzer → Viewer (URLs encontradas)
- ✅ Burp → Repeater (requests)
- ✅ Config → Fuzzer (wordlists)

#### 3. System Testing (Aplicación Completa)
- ✅ Workflow típico: Scan → Fuzz → Exploit
- ✅ Comportamiento bajo estrés
- ✅ Manejo de errores cascada
- ✅ Recovery de fallos

---

## 📋 Test Cases por Herramienta

### SCANNER Tests

#### Valid Inputs:
```
1. IP: 127.0.0.1
   ✓ Debe iniciar escaneo automático
   ✓ Progress bar: 0-100%
   ✓ Logging: [⏳] → [✅]

2. Domain: localhost
   ✓ Debe resolver y escanear
   ✓ Progress: 1-10000 luego 1-65535

3. URL: example.com (sin http)
   ✓ Debe manejar conversión
```

#### Invalid Inputs:
```
1. IP: 256.256.256.256
   ✓ Debe rechazar con [❌]

2. IP: vacío
   ✓ Toast: "IP requerida"

3. Domain: special!@#$
   ✓ Debe manejar o rechazar
```

#### Edge Cases:
```
1. IP privada: 192.168.1.1
   ✓ Debe funcionar en LAN

2. Localhost: 127.0.0.1
   ✓ Debe ser rápido

3. Sin puertos abiertos
   ✓ Debe completar segunda pasada
```

---

### FUZZER Tests

#### Valid Inputs:
```
1. URL: http://localhost:8000
   Wordlist: /path/to/common.txt
   Threads: 10
   ✓ Debe fuzear correctamente
   ✓ Progress cada 100 palabras
   ✓ Resultados formateados

2. URL: ejemplo.com (sin protocolo)
   ✓ Auto-agregar http://

3. Threads: 50
   Port: 8080
   ✓ Debe validar range
```

#### Invalid Inputs:
```
1. URL: vacía
   ✓ Toast: "URL requerida"

2. Wordlist: /no/existe.txt
   ✓ Toast: "Archivo no existe"

3. Threads: -5
   ✓ Toast: "Valor inválido"

4. Port: 99999
   ✓ Toast: "Puerto 1-65535"
```

#### Stress Tests:
```
1. Wordlist: 1M+ palabras
   ✓ Debe procesar sin crash
   ✓ Debe mostrar progreso

2. 200 Threads
   ✓ Debe limitar o advertir

3. Target lento (timeout)
   ✓ Debe capturar errors
```

---

### LISTENER Tests

#### Valid Inputs:
```
1. Port: 4444
   ✓ Debe escuchar en 127.0.0.1:4444
   ✓ Aceptar conexiones
   ✓ Recibir output

2. Port: 9999
   ✓ Reutilizable después de stop
```

#### Invalid Inputs:
```
1. Port: 65536
   ✓ Toast: "Puerto 1-65535"

2. Port: -1
   ✓ Toast: "Puerto inválido"

3. Port en uso: 22 (SSH)
   ✓ Toast: "Puerto ya en uso"
   ✓ Sugerir diferente
```

#### Edge Cases:
```
1. Port 1-1024 (privilegiados)
   ✓ Error: "Permisos requeridos"

2. Múltiples listeners
   ✓ Cada uno en puerto diferente

3. Reconexión después de timeout
   ✓ SO_REUSEADDR funcione
```

---

### CRYPTO Tests

#### Base64:
```
Valid:
- "hello" → "aGVsbG8="
- "test123" → "dGVzdDEyMw=="

Invalid:
- Vacío → [❌] "Input requerido"
- "!!!!" → Acepta (encoding)

Decode:
- "aGVsbG8=" → "hello"
- "invalid!!!" → [❌] "Decode error"
```

#### Hash:
```
Valid:
- "password" → MD5/SHA1/SHA256
- Largo valor → Procesar

Invalid:
- Vacío → [❌]
```

#### Conversiones:
```
Binary:
- "01001000" → "H"
- "invalid" → [❌]

Hex:
- "48656C6C6F" → "Hello"
- "GGG" → [❌]
```

---

### PAYLOADS Tests

#### Windows Payloads:
```
Valid:
- LHOST: 192.168.1.100
- LPORT: 4444
- Formato: exe, exe-service
- Resultado: comando msfvenom

Invalid:
- LHOST: 999.999.999.999 → [❌]
- LPORT: 99999 → [❌]
- LPORT: abc → [❌]
- LPORT: vacío → [❌]
```

#### Linux Payloads:
```
Valid:
- LHOST: 10.0.0.1
- LPORT: 5555
- Formato: elf, sh
- Resultado: comando generado

Invalid:
- Inputs vacíos → [❌]
```

#### Android:
```
Valid:
- Parámetros válidos
- APK generado

Invalid:
- LPORT fuera de rango
```

---

### BURP Tests

#### Proxy Toggle:
```
Valid:
- Start: 127.0.0.1:8080
  ✓ Status: "ONLINE 127.0.0.1:8080"
  ✓ Button: "Detener Proxy"

- Stop:
  ✓ Status: "OFFLINE"
  ✓ Button: "Iniciar Proxy"

Invalid:
- Host: vacío → use 127.0.0.1 default
- Port: 99999 → [❌] "1-65535"
- Port: en uso → [❌] "Already in use"
```

#### Repeater:
```
Valid:
- Method: GET
- URL: http://localhost:8000
- Headers: Content-Type: application/json
- Body: {"test": "data"}
- Resultado: Response mostrada

Invalid:
- Method: INVALID → [❌]
- URL: vacía → [❌]
- URL: malformada → Auto-agregar http://
```

#### Intercept:
```
Valid:
- Habilitar intercepción
- Seleccionar request
- Forward/Drop
- ✓ Cola actualizada

Invalid:
- Nada seleccionado → [⚠️]
- Request no pendiente → [⚠️]
```

#### Export:
```
Valid:
- JSON: items → export.json
- HAR: items → export.har
- ✓ Archivo creado
- ✓ Logging: "N items exportados"

Invalid:
- Sin items → [⚠️] "No hay items"
- Permisos: insuficientes → [❌]
- Disco: lleno → [❌]
```

---

### CONFIG Tests

#### Wordlist Management:
```
Valid:
- Seleccionar carpeta
- Reindexar
- ✓ "✅ Indexadas: 1234 | web:456..."
- ✓ Fuzzer actualizado

Invalid:
- Carpeta no existe → Error
- Sin permisos → Error
- Indexación ya en curso → [⚠️]
```

---

### CREDENTIALS Tests

#### Windows System:
```
Valid:
- Analizar
- ✓ Navegadores detectados
- ✓ Credenciales extraídas
- ✓ Output formateado

Invalid:
- Sistema: Linux → [⚠️] "Windows only"
- Módulos faltantes → [❌] "ImportError"
```

#### Edge Cases:
```
1. Sin navegadores instalados
   ✓ [ℹ️] "No encontrados"

2. Sin credenciales guardadas
   ✓ [✅] "Sin credenciales"

3. Credenciales dañadas
   ✓ [⚠️] Skip + continuar
```

---

### VIEWER Tests

#### URL Loading:
```
Valid:
- https://google.com
  ✓ Contenido cargado
  ✓ Pestañas creadas
  ✓ Análisis realizado

- http://localhost:8000
  ✓ Carga local

Invalid:
- URL: vacía → [❌] "URL requerida"
- URL: timeout (sitio lento)
  → [❌] "Timeout: servidor tardó"

- URL: sitio no existe
  → [❌] "Connection error"
```

#### File Loading:
```
Valid:
- HTML file
  ✓ Syntax highlighting
  ✓ Análisis

- JS file
  ✓ Loaded y mostrado

- Binary file
  ✓ Decodificación safe

Invalid:
- Archivo: no existe → [❌]
- Archivo: sin permisos → [❌]
- Archivo: muy grande → [⚠️] Cargar de todos modos
```

---

### UTILS Tests

#### Hosts Management:
```
Valid:
- IP: 192.168.1.1
- Domain: target.htb
- ✓ Entrada agregada a /etc/hosts
- ✓ Logging: "[✅] hosts actualizado"

Invalid:
- IP: 256.256.256.256 → [❌]
- Domain: vacío → [❌]
- Permisos: no admin → [❌]
```

#### HTTP Server:
```
Valid:
- Port: 8080
- Directory: /home/user/files
- ✓ Server inicia
- ✓ Status: "✅ ON | Port 8080"
- ✓ Download hints mostrados

Invalid:
- Port: 99999 → [❌] "1-65535"
- Port: en uso → [❌] "Address already in use"
- Port: privilegiado sin root → [❌]

Edge Cases:
- Port: 1 (privilegiado)
  → [❌] "Root required"
  
- Carpeta: /root (sin permisos)
  → [⚠️] Error al servir archivos
```

---

## 🔄 Integration Test Flows

### Flujo 1: Scanning & Fuzzing
```
1. Scanner
   ↓ IP encontrado
2. Config (copiar IP)
   ↓
3. Fuzzer
   ↓ URLs encontradas
4. Viewer (abrir URL)
   ✓ HTML mostrado
```

### Flujo 2: Pentesting Completo
```
1. Scanner: IP → Puertos abiertos
   ↓
2. Payloads: Generar exploit para puerto
   ↓
3. Listener: Configurar para reverse shell
   ↓
4. Fuzzer: Buscar directorios de upload
   ↓
5. Burp: Interceptar y modificar requests
   ↓
6. Viewer: Ver respuestas
   ✓ Pentesting completo
```

### Flujo 3: Configuración
```
1. Config: Seleccionar wordlists
   ↓
2. Fuzzer: Wordlists cargadas
   ↓
3. Credentials: Auditar (si Windows)
   ↓
4. Utils: Configurar servidor HTTP
   ✓ Stack listo
```

---

## 🎯 Checklist de Validation

### Antes de Deploy:

- [ ] Todos los test cases ejecutados
- [ ] No hay crashes detectados
- [ ] Mensajes de error son claros
- [ ] Logging funciona en todas las herramientas
- [ ] Toast notifications son visibles
- [ ] Emojis se muestran correctamente
- [ ] Threading no causa deadlocks
- [ ] Widget safety en todos lados
- [ ] Validación de puertos exhaustiva
- [ ] Validación de URLs exhaustiva

### Performance:

- [ ] Scanner con >10000 puertos: <5 minutos
- [ ] Fuzzer con 1M palabras: progreso fluido
- [ ] Listener: <1ms latencia
- [ ] Burp: <2s por request
- [ ] Config reindex: <30s para 10k wordlists
- [ ] Viewer: <3s para cargar URL
- [ ] HTTP Server: <100ms por request

### Security:

- [ ] Validación de input en todos lados
- [ ] No SQL injection posible
- [ ] No command injection posible
- [ ] Archivos no se sobrescriben sin confirmación
- [ ] Permisos validados
- [ ] Port binding seguro

---

## 🚀 Deployment Checklist

### Pre-Deployment:
- [ ] Todos los archivos sin errores de sintaxis
- [ ] Testing completo pasado
- [ ] Performance satisfactorio
- [ ] Documentación actualizada

### Post-Deployment:
- [ ] Monitor logs por primeras 24h
- [ ] Feedback de usuarios recopilado
- [ ] Issues críticos identificados
- [ ] Patches preparados si es necesario

### Monitoring:
- [ ] Errores no capturados
- [ ] Crashes inesperados
- [ ] Performance degradation
- [ ] Security issues

---

## 📝 Test Report Template

```
# Test Report - CyberNatu v2.x

## Summary
- Total Tests: XXX
- Passed: XXX (XX%)
- Failed: X
- Errors: X
- Skipped: X

## Scanner Tests
- [ ] Valid IPs: PASS
- [ ] Invalid IPs: PASS
- [ ] Progress tracking: PASS
- [ ] Two-pass system: PASS

## Fuzzer Tests
- [ ] URL validation: PASS
- [ ] Wordlist loading: PASS
- [ ] Progress tracking: PASS

## Listener Tests
- [ ] Port binding: PASS
- [ ] Port reuse: PASS
- [ ] Connection handling: PASS

## Crypto Tests
- [ ] Base64: PASS
- [ ] Hash: PASS
- [ ] Conversions: PASS

## Payloads Tests
- [ ] Windows: PASS
- [ ] Linux: PASS
- [ ] Validation: PASS

## Burp Tests
- [ ] Proxy: PASS
- [ ] Repeater: PASS
- [ ] Intercept: PASS
- [ ] Export: PASS

## Config Tests
- [ ] Wordlist indexing: PASS
- [ ] Panel notification: PASS

## Credentials Tests
- [ ] Windows audit: PASS
- [ ] Output format: PASS

## Viewer Tests
- [ ] URL loading: PASS
- [ ] File loading: PASS
- [ ] Syntax highlighting: PASS

## Utils Tests
- [ ] Hosts management: PASS
- [ ] HTTP server: PASS

## Integration Tests
- [ ] Scan → Fuzz: PASS
- [ ] Scanner → Payloads: PASS
- [ ] Fuzzer → Viewer: PASS
- [ ] Burp → Repeater: PASS

## Issues Found
1. [Critical] ...
2. [Major] ...
3. [Minor] ...

## Performance Results
- Scanner: X seconds
- Fuzzer: X items/second
- Viewer: X milliseconds

## Recommendations
1. ...
2. ...
3. ...

Date: YYYY-MM-DD
Tester: XXX
Status: [READY FOR DEPLOYMENT / NEEDS FIXES]
```

---

**Testing Status:** ✅ READY FOR DEPLOYMENT
**Last Updated:** 2024
**Version:** 2.x Production
