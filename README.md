# Reconocimiento de Subdominios en Shodan

Herramienta OSINT pasiva para enumerar todos los subdominios indexados por Shodan de un dominio. Diseñada para bug bounty, divulgación responsable y workflows de investigación de seguridad.

## Características

- Enumeración pasiva de subdominios DNS (Shodan DNS)
- Solo muestra URLs completas: https://subdominio.dominio.com
- 100% pasivo (sin escaneo activo)
- Resultados guardados por dominio en results/
- Rápido y ligero: usa directamente la API de Shodan

## Requisitos

- Python 3.9+
- Clave API de Shodan (puedes verla en tu cuenta de Shodan)

## 🚀 Instrucciones de Uso COMPLETAS

### ✅ 1) Clonar el repositorio
```
git clone https://github.com/hominid0/subdomainrecon-shodan.git
cd subdomainrecon-shodan
```

### 🐍 2) Crear y activar entorno virtual (recomendado)
```
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate     # Windows (PowerShell/cmd)
```

### 📦 3) Instalar dependencias
```
pip install -r requirements.txt
```

### 🔑 4) Configurar la API Key de Shodan (OBLIGATORIO)
```
export SHODAN_API_KEY="TU_API_KEY_AQUI"  # Linux/Mac
# $env:SHODAN_API_KEY="TU_API_KEY_AQUI"  # Windows PowerShell
```

### ▶️ 5) Ejecutar el script
```
python subdomainrecon_shodan.py example.com
```

### 📁 6) Ver resultados
```
ls -la results/
cat results/example.com.txt
```

### 🛑 7) Salir del entorno virtual (opcional)
```
deactivate
```
```

## ⚠️ Legal disclaimer

This tool is intended for **authorized security testing only**.

Use it **only on assets you own or have explicit permission to test**.  
The author assumes **no responsibility for misuse**.

---

## 🤝 Contributions

Pull requests, improvements and suggestions are welcome.

If you find this tool useful ⭐ the repository!
