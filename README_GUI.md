# TCP/IP Misconfiguration Analyzer - GUI Edition

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- All dependencies from `requirements.txt`

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Run the GUI application
python gui_app.py
```

---

## ✨ Features

### Beautiful Modern Interface
- **Dark Blue Cyberpunk Theme** with gradient backgrounds
- **High-tech aesthetic** with semi-transparent panels and rounded corners
- **Professional color scheme**: Cyan, electric blue, and neon accents
- **Background images** integrated from your `/images` folder
- **Smooth hover animations** on all interactive elements
- **Responsive design** with optimized layout

### Fully Functional Analysis Tools

#### 📊 Network Scanning
- **TCP SYN Probes** - Detect open/closed ports
- **TCP ACK Probes** - Identify unfiltered ports and firewall rules
- **ICMP Probes** - Test target reachability
- **Repeated ICMP Analysis** - Detect TTL stability and IP ID predictability

#### 📈 Comprehensive Results
- **Overview Tab**: Summary of open ports, risk scores, OS detection
- **Findings Tab**: Critical security issues and vulnerabilities
- **Mitigations Tab**: Actionable recommendations to fix issues
- **Raw Data Tab**: Complete JSON data export

#### 🎯 Advanced Features
- **Risk Scoring System** (0-100 scale)
- **OS Fingerprinting** via TTL analysis
- **IP ID Predictability Detection** (critical security finding)
- **Service Identification** on detected ports
- **Multi-threaded Scanning** (non-blocking UI)
- **Automatic Report Generation** (JSON + TXT)

---

## 🎨 UI Components

### Left Sidebar (Input Panel)
- Beautiful background image integration
- Clean target IP input field with placeholder
- Port range selector (From/To ports)
- Animated "START SCAN" button with gradient
- Live progress bar and status updates

### Right Content Area (Results)
- Professional header with project title
- 4 tabbed views for comprehensive data presentation
- Color-coded text output:
  - **Cyan** (#00ffcc): Technical data
  - **Orange** (#ffaa00): Security warnings
  - **Green** (#88ff88): Recommended fixes
  - **Gray** (#cccccc): Raw data

---

## 🎯 How to Use

### Basic Scan
1. Enter target IP (e.g., `8.8.8.8` or `127.0.0.1`)
2. Adjust port range if needed (default: 20-443)
3. Click **⚡ START SCAN**
4. Wait for completion (progress updates in real-time)
5. Review results in the tabbed interface

### Interpreting Results

**Overview Tab**
- Quick summary of scan results
- Open/closed/filtered port counts
- ICMP reachability status
- Detected operating system
- Risk assessment score

**Findings Tab**
- Critical security issues identified
- Detailed vulnerability assessments
- Risk summary and threat analysis

**Mitigations Tab**
- Step-by-step remediation recommendations
- Security hardening suggestions
- Configuration fixes

**Raw Data Tab**
- Complete JSON export of all findings
- Use for integration with other tools
- Machine-readable format

---

## ⚙️ Technical Details

### Architecture
- **Single-file GUI** (`gui_app.py`) for simplicity
- **Minimal dependencies**: Only PyQt6 added to Scapy
- **Non-blocking operations**: Worker threads prevent UI freezing
- **Real-time feedback**: Live status updates during scanning

### Code Organization
```
gui_app.py
├── AnalysisWorker (QThread)
│   └── Runs scans without blocking UI
├── StyledCard (QFrame)
│   └── Reusable styled container
├── ModernButton (QPushButton)
│   └── Custom button with animations
└── TCPIPAnalyzerGUI (QMainWindow)
    ├── init_ui()
    ├── create_left_panel()
    ├── create_header()
    ├── create_tabs()
    └── Scan coordination
```

### Key Features Implementation
- **Gradient backgrounds**: QLinearGradient with RGB transitions
- **Animations**: QPushButton with stylesheet hover effects
- **Threading**: QThread for non-blocking network operations
- **Image integration**: Background images from `/images` folder
- **Color coding**: ANSI-style text coloring in QTextEdit

---

## 🔒 Security Notes

### Administrator Rights
- Windows: Run command prompt as Administrator
- Linux/Mac: Use `sudo` or ensure raw socket permissions
- GUI will display error if insufficient privileges

### Network Safety
- Only scan networks/hosts you own or have permission to test
- Default targets are localhost (127.0.0.1) and public DNS (8.8.8.8)
- Reports are automatically saved to `/reports` folder

---

## 📁 Generated Files

After each scan, the application generates:
```
reports/
├── report_<IP>_<TIMESTAMP>.json    (Machine-readable)
└── report_<IP>_<TIMESTAMP>.txt     (Human-readable)
```

---

## 🐛 Troubleshooting

### "Permission denied" Error
**Solution**: Run as Administrator (Windows) or with sudo (Linux/Mac)

### GUI doesn't appear
**Solution**: Ensure PyQt6 is installed: `pip install PyQt6`

### Slow scanning
**Solution**: This is normal for TCP/IP analysis. Reduce port range if needed.

### Image background not showing
**Solution**: Ensure `/images` folder contains img1.png, img2.jpg, img3.jpg

---

## 📦 Dependencies

```
scapy==2.7.0        # Network packet analysis
PyQt6==6.11.0       # Modern GUI framework
```

---

## 🎓 Educational Value

This tool demonstrates:
- TCP/IP network stack analysis
- Active probing techniques
- Python GUI development with PyQt6
- Multi-threaded programming
- Security risk assessment
- Professional UI/UX design

---

**Created**: 2026-06-21  
**Project**: Analysis of TCP/IP Stack Misconfigurations using Active Probing
