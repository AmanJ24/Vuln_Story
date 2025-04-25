# 🛡️ Vuln_Story: Vulnerability Story Teller

<div align="center">

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-blue)

</div>

🚀 A powerful tool that transforms technical vulnerability scan results into human-readable reports with AI-powered explanations. Vuln_Story parses Burp Suite XML outputs and uses the AWAN LLM API to generate comprehensive vulnerability explanations, producing professional HTML and PDF reports for developers and security teams.

## ✨ Features

🤖 **AI-Powered Explanations**
- Generates clear, structured explanations for each vulnerability using AWAN LLM
- Converts technical findings into comprehensible stories

📄 **Multiple Input Formats**
- Currently supports Burp Suite XML scan results
- More parsers planned for future releases

🎯 **Dual Output Formats**
- Generate professional HTML reports
- Create polished PDF documents
- Choose one or both formats as needed

📊 **Structured Reports**
- Well-organized vulnerability details
- Severity classifications
- Comprehensive remediation guidance
- User-friendly formatting

🔧 **Dual Interfaces**
- Command Line Interface (CLI) for scripting and automation
- Web Interface for easy file uploads and report downloads

💪 **Resilient Processing**
- Robust error handling
- Automatic retries for API issues
- Detailed logging and debugging options

## 📋 Prerequisites

Before you begin, ensure you have the following:

✅ Python 3.11 or higher installed
✅ AWAN LLM API key 
✅ `wkhtmltopdf` installed for PDF generation
✅ Access to a terminal or command prompt
✅ Basic familiarity with command line operations

## 🔧 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/AmanJ24/Vuln_Story.git
cd Vuln_Story
```

### 2️⃣ Set up Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 3️⃣ Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 4️⃣ Install wkhtmltopdf

<details>
<summary>📥 Installation Instructions by OS</summary>

#### Linux
- **Debian/Ubuntu/Kali**:
  ```bash
  sudo apt-get install wkhtmltopdf
  ```
- **CentOS/RHEL**:
  ```bash
  sudo yum install wkhtmltopdf
  ```

#### macOS
```bash
brew install wkhtmltopdf
```

#### Windows
- Download installer from [wkhtmltopdf website](https://wkhtmltopdf.org/downloads.html)
- Run the installer and follow the setup wizard
</details>

### 5️⃣ Configure API Key
```bash
export AWA_API_KEY="your-api-key-here"
```

## 🚀 Usage

### 🖥️ Command Line Interface (CLI)

Transform your Burp Suite XML reports into detailed vulnerability stories:

```bash
# Generate both HTML and PDF reports
python main.py -i path/to/burp_scan.xml -o reports -f both

# Generate only HTML report
python main.py -i path/to/burp_scan.xml -f html

# Generate only PDF report
python main.py -i path/to/burp_scan.xml -f pdf

# Use a specific AWAN LLM model
python main.py -i path/to/burp_scan.xml --model "Meta-Llama-3-8B-Instruct"

# Provide AWAN API key directly
python main.py -i path/to/burp_scan.xml --api-key "your-api-key-here"

# Enable debug logging
python main.py -i path/to/burp_scan.xml --debug
```

### 🌐 Web Interface

Launch the interactive web interface:

```bash
# Default Configuration (Port 5000)
python main.py -m web

# Custom Port and Network Access
python main.py -m web -p 8080 --host 0.0.0.0

# Debug Mode
python main.py -m web --debug
```

#### 📝 Using the Web Interface

1. 🔍 Open your browser and navigate to `http://localhost:5000`
2. 📤 Upload your Burp Suite XML file
3. ✅ Select desired output format(s)
4. 🚀 Click "Generate Report"
5. 📥 Download your generated report(s)

## 📊 Report Structure

Your generated report will include comprehensive sections for each vulnerability:

🔍 **Vulnerability Details**
- Name and classification
- Affected URL and parameters
- Severity level assessment

🎯 **Discovery Narrative**
- How attackers identify such vulnerabilities
- Common discovery methods and tools

⚔️ **Exploitation Scenario**
- Step-by-step explanation of potential exploitation
- Clear, non-technical description of the attack process

💥 **Impact Analysis**
- Detailed consequences of successful exploitation
- Business and technical impact assessment

🛡️ **Remediation Guidelines**
- Clear, actionable fix recommendations
- Best practices for prevention

## ⚙️ Configuration Options

### 🎮 Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-m, --mode` | Mode to run the application in (`cli` or `web`) | `cli` |
| `-i, --input` | Path to the input vulnerability scan file | Required in CLI mode |
| `-o, --output-dir` | Directory to save the generated reports | `reports` |
| `-f, --format` | Output report format(s) (`html`, `pdf`, or `both`) | `both` |
| `-p, --port` | Port to run the web server on (web mode only) | `5000` |
| `--host` | Host address to bind the web server to (web mode only) | `127.0.0.1` |
| `--api-key` | AWAN LLM API key | Uses environment variable if not specified |
| `--model` | AWAN LLM model to use | `Meta-Llama-3-8B-Instruct` |
| `--debug` | Enable debug logging for more detailed output | Disabled by default |

### 🔐 Environment Variables

| Variable | Description |
|----------|-------------|
| `AWA_API_KEY` | Your AWAN LLM API key (alternative to --api-key) |

## 🤝 Contributing

We welcome contributions! Here's how you can help make Vuln_Story better:

### 🐛 Report Bugs
- Open an issue with detailed steps to reproduce
- Include relevant error messages and logs
- Describe expected vs actual behavior

### 💡 Suggest Features
- Open an issue describing your idea
- Explain the use case and value
- Discuss potential implementation approaches

### 🔨 Submit Code
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

#### Pull Request Guidelines
✅ Follow existing code style
✅ Add/update tests as needed
✅ Update documentation
✅ Provide clear PR description

## 📜 License

This project is pending license selection. Check back soon for updates.

## 🙏 Acknowledgments

Special thanks to:
- 🤖 AWAN LLM API Team for their powerful AI capabilities
- 🛡️ PortSwigger for Burp Suite
- 👥 All our amazing contributors

## 📬 Connect & Support

- Submit an Issue: [GitHub Issues](https://github.com/amangupta0709/VULN_STORY_TELLER/issues)
- Contact: amangupta0709@gmail.com

---

<div align="center">
Made with ❤️ by Aman Gupta

⭐ Star this repository if you find it helpful!
</div>

