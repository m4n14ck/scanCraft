ScanCraft - Gestor de Escaneos Nmap
Descripción
ScanCraft es una herramienta que simplifica el uso de Nmap, permitiendo crear, guardar y ejecutar escaneos de red personalizados sin necesidad de recordar comandos complejos. Convierte a Nmap de una utilidad de línea de comandos en una suite completa de escaneo y análisis de redes.

Características
🛠️ Gestión de Comandos
Crear y guardar comandos Nmap personalizados

Listar y organizar todos los comandos guardados

Editar y actualizar comandos existentes

Eliminar comandos que ya no se usen

Exportar e importar configuraciones entre sistemas

🔍 Ejecución de Escaneos
Ejecutar escaneos preconfigurados con selección simple

Resultados en tiempo real durante la ejecución

Guardado opcional de resultados después del escaneo

Detección inteligente de escaneos interrumpidos (Ctrl+C)

Validación automática de parámetros

📊 Análisis de Resultados
Visualización de resultados guardados

Análisis detallado automático de escaneos

Estadísticas completas de hosts, puertos y servicios

Detección automática de subredes analizadas

Recomendaciones de seguridad basadas en hallazgos

Métricas de rendimiento y resumen ejecutivo

🌐 Información de Red
Visualización de interfaces de red

Tabla de rutas del sistema

Conexiones de red establecidas

Verificación de conectividad a internet

📈 Estadísticas y Reportes
Estadísticas básicas del sistema

Análisis avanzado de escaneos específicos

Métricas de uso y espacio en disco

Resumen ejecutivo de escaneos completados

Ventajas
Para Usuarios Novatos
No requiere memorizar comandos Nmap complejos

Interfaz intuitiva y guiada paso a paso

Validación automática de parámetros

Ejemplos integrados para aprendizaje

Para Usuarios Avanzados
Ahorra tiempo en escaneos repetitivos

Organización centralizada de comandos

Análisis automático de resultados

Portabilidad de configuraciones entre equipos

Técnicas
Una sola ejecución por escaneo (eficiente)

Guardado opcional de resultados

Manejo seguro de interrupciones

Sistema de respaldo y restauración

Instalación y Compilación
Prerrequisitos

# Instalar Crystal (Ubuntu/Debian)
curl -fsSL https://crystal-lang.org/install.sh | sudo bash

# Instalar Nmap y dependencias
sudo apt update
sudo apt install crystal nmap iproute2 net-tools iputils-ping libssl-dev libxml2-dev libyaml-dev libgmp-dev libz-dev

# Clonar o descargar el código fuente
# Compilar el proyecto
crystal build scanner.cr -o scancraft --release

# Hacer ejecutable
chmod +x scancraft

# Ejecutar el programa
./scancraft
