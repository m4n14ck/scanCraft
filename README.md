# ScanCraft - Gestor de Escaneos Nmap

<img width="888" height="585" alt="image" src="https://github.com/user-attachments/assets/ad13f537-cbe0-4955-ad1c-6914122801cb" />

# 📖 Descripción
Interfaz interactiva que simplifica el uso de Nmap mediante la gestión de comandos personalizados, ejecución de escaneos y análisis automatizado de resultados.

# Características Principales
  Gestión de Comandos
Crear, editar y eliminar comandos Nmap personalizados

Guardar configuraciones para uso repetido

Exportar/importar configuraciones entre sistemas


# 🚀 Ejecución de Escaneos

Ejecutar escaneos preconfigurados con un clic

Mostrar resultados en tiempo real

Guardado opcional de resultados

# 📊 Análisis 
Análisis automático de resultados de escaneos

Estadísticas de hosts, puertos y servicios

Detección de subredes y recomendaciones de seguridad

Métricas de rendimiento y resúmenes ejecutivos

# 🌐 Herramientas de Red
Información de interfaces de red

Tabla de rutas y conexiones establecidas

Verificación de conectividad

# 🛠️ Instalación

# Instalar Crystal
curl -fsSL https://crystal-lang.org/install.sh | sudo bash

# Instalar dependencias (Ubuntu/Debian)
sudo apt install nmap iproute2 net-tools iputils-ping

crystal build scanner.cr -o scancraft --release
chmod +x scancraft

./scancraft
