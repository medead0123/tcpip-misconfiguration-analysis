#!/usr/bin/env python3
"""
Modern GUI for TCP/IP Misconfiguration Analyzer
Simple, elegant, high-tech interface with professional styling
"""

import json
import os
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QTabWidget, QTextEdit,
    QProgressBar, QScrollArea, QFrame, QGridLayout, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread, QSize
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QLinearGradient, QPainter, QBrush, QPalette
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve

# Import analyzer functions
from tcpip_misconfig_analyzer import (
    tcp_syn_probe, tcp_ack_probe, icmp_probe, repeated_icmp_analysis,
    analyze_results, calculate_score, generate_mitigations, generate_reports,
    get_service_name
)


class AnalysisWorker(QThread):
    """Worker thread for running analysis without blocking GUI"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, target, ports):
        super().__init__()
        self.target = target
        self.ports = ports
        self.results = {}

    def run(self):
        try:
            self.progress.emit("Starting TCP SYN probes...")
            syn_results = [tcp_syn_probe(self.target, port) for port in self.ports]
            self.progress.emit(f"Completed {len(syn_results)} SYN probes. Starting ACK probes...")

            ack_results = [tcp_ack_probe(self.target, port) for port in self.ports]
            self.progress.emit("ACK probes complete. Running ICMP analysis...")

            icmp_result = icmp_probe(self.target)
            self.progress.emit("ICMP probe complete. Analyzing repeated patterns...")

            repeat_analysis = repeated_icmp_analysis(self.target, count=3)
            self.progress.emit("Analysis complete. Generating findings...")

            analysis = analyze_results(self.target, syn_results, ack_results, icmp_result, repeat_analysis)
            score_data = calculate_score(analysis, ack_results, icmp_result, repeat_analysis)
            mitigations = generate_mitigations(analysis, ack_results, icmp_result, repeat_analysis)

            self.results = {
                "target": self.target,
                "syn_results": syn_results,
                "ack_results": ack_results,
                "icmp_result": icmp_result,
                "repeat_analysis": repeat_analysis,
                "analysis": analysis,
                "score_data": score_data,
                "mitigations": mitigations,
                "timestamp": datetime.now().isoformat()
            }

            self.progress.emit("Generating reports...")
            try:
                generate_reports(self.target, syn_results, ack_results, icmp_result,
                               repeat_analysis, analysis, score_data, mitigations)
            except Exception as report_err:
                print(f"Warning: Report generation failed: {report_err}")

            self.progress.emit("✓ Scan complete!")
            self.finished.emit(self.results)

        except PermissionError:
            self.error.emit("PERMISSION DENIED: This tool requires administrator/root privileges.")
        except Exception as e:
            error_msg = f"Scan Error: {str(e)}"
            print(f"Worker thread error: {error_msg}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            self.error.emit(error_msg)


class StyledCard(QFrame):
    """Custom styled card with semi-transparent background"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(45, 25, 70, 0.7);
                border-radius: 20px;
                border: 1.5px solid rgba(200, 100, 255, 0.25);
            }
        """)
        self.setFrameShape(QFrame.Shape.StyledPanel)


class ModernButton(QPushButton):
    """Custom styled button with hover animations"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #a855f7, stop:1 #ec4899);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #c084fc, stop:1 #f472b6);
                border: 2px solid rgba(236, 72, 153, 0.6);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #9333ea, stop:1 #be185d);
            }
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class TCPIPAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker_thread = None
        self.current_results = None
        self.init_ui()
        self.apply_theme()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("TCP/IP Misconfiguration Analyzer")
        self.setGeometry(100, 100, 1400, 900)
        self.setWindowIcon(self.create_gradient_icon())

        # Main container
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Left sidebar with background image
        left_panel = self.create_left_panel()
        main_layout.addWidget(left_panel, 1)

        # Right content area
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(20, 20, 20, 20)
        right_layout.setSpacing(15)

        # Header
        header = self.create_header()
        right_layout.addWidget(header)

        # Tabs
        tabs = self.create_tabs()
        right_layout.addWidget(tabs, 1)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        right_widget.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a0f2e, stop:0.5 #16213e, stop:1 #0f3460);
            }
        """)
        main_layout.addWidget(right_widget, 2)

    def create_left_panel(self):
        """Create left sidebar with input controls"""
        panel = QFrame()
        panel.setMinimumWidth(380)
        
        # Set background image using pixmap
        try:
            pixmap = QPixmap("images/img1.png")
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaledToWidth(380, Qt.TransformationMode.SmoothTransformation)
                palette = panel.palette()
                palette.setBrush(panel.backgroundRole(), QBrush(scaled_pixmap))
                panel.setPalette(palette)
                panel.setAutoFillBackground(True)
        except:
            pass  # Fall back to solid color if image not found
        
        panel.setStyleSheet("""
            QFrame {
                background-color: rgba(20, 10, 40, 200);
                border-right: 2px solid rgba(200, 100, 255, 0.2);
            }
        """)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # Add overlay card
        card = StyledCard()
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(15)

        # Title
        title = QLabel("Network Scan")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #f472b6; letter-spacing: 1px;")
        card_layout.addWidget(title)

        # Target IP
        ip_label = QLabel("Target IP Address")
        ip_label.setStyleSheet("color: #d8b4fe; font-size: 12px; font-weight: bold; letter-spacing: 0.5px;")
        card_layout.addWidget(ip_label)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 8.8.8.8 or 127.0.0.1")
        self.ip_input.setText("127.0.0.1")
        self.ip_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 0.08);
                border: 2px solid rgba(168, 85, 247, 0.3);
                border-radius: 10px;
                padding: 12px;
                color: #e9d5ff;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 2px solid #ec4899;
                background-color: rgba(255, 255, 255, 0.12);
            }
        """)
        card_layout.addWidget(self.ip_input)

        # Port range
        port_label = QLabel("Port Range")
        port_label.setStyleSheet("color: #d8b4fe; font-size: 12px; font-weight: bold; letter-spacing: 0.5px;")
        card_layout.addWidget(port_label)

        port_layout = QHBoxLayout()
        port_layout.setSpacing(12)

        port_start_label = QLabel("From:")
        port_start_label.setStyleSheet("color: #c084fc; font-weight: 600;")
        port_layout.addWidget(port_start_label)

        self.port_start = QSpinBox()
        self.port_start.setMinimum(1)
        self.port_start.setMaximum(65535)
        self.port_start.setValue(20)
        self.port_start.setStyleSheet("""
            QSpinBox {
                background-color: rgba(255, 255, 255, 0.08);
                border: 2px solid rgba(168, 85, 247, 0.3);
                border-radius: 8px;
                padding: 6px;
                color: #e9d5ff;
                font-weight: bold;
            }
        """)
        port_layout.addWidget(self.port_start)

        port_end_label = QLabel("To:")
        port_end_label.setStyleSheet("color: #c084fc; font-weight: 600;")
        port_layout.addWidget(port_end_label)

        self.port_end = QSpinBox()
        self.port_end.setMinimum(1)
        self.port_end.setMaximum(65535)
        self.port_end.setValue(443)
        self.port_end.setStyleSheet("""
            QSpinBox {
                background-color: rgba(255, 255, 255, 0.08);
                border: 2px solid rgba(168, 85, 247, 0.3);
                border-radius: 8px;
                padding: 6px;
                color: #e9d5ff;
                font-weight: bold;
            }
        """)
        port_layout.addWidget(self.port_end)
        card_layout.addLayout(port_layout)

        # Scan button
        self.scan_btn = ModernButton("⚡ START SCAN")
        self.scan_btn.setMinimumHeight(54)
        self.scan_btn.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self.scan_btn.clicked.connect(self.start_scan)
        card_layout.addWidget(self.scan_btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid rgba(168, 85, 247, 0.3);
                border-radius: 8px;
                background-color: rgba(0, 0, 0, 0.2);
                height: 8px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #a855f7, stop:1 #ec4899);
                border-radius: 6px;
            }
        """)
        self.progress_bar.setMaximum(0)
        self.progress_bar.setVisible(False)
        card_layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #a78bfa; font-size: 11px; letter-spacing: 0.3px;")
        self.status_label.setWordWrap(True)
        card_layout.addWidget(self.status_label)

        card_layout.addStretch()

        layout.addWidget(card)
        layout.addStretch()

        return panel

    def create_header(self):
        """Create top header with title and info"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(168, 85, 247, 0.08), stop:1 rgba(236, 72, 153, 0.08));
                border-radius: 16px;
                border: 1.5px solid rgba(200, 100, 255, 0.2);
            }
        """)
        layout = QVBoxLayout(header)
        layout.setContentsMargins(24, 18, 24, 18)

        title = QLabel("🔒 TCP/IP Misconfiguration Analysis")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #f472b6;")
        layout.addWidget(title)

        subtitle = QLabel("Advanced network security assessment and threat detection")
        subtitle.setFont(QFont("Segoe UI", 11))
        subtitle.setStyleSheet("color: #c084fc;")
        layout.addWidget(subtitle)

        return header

    def create_tabs(self):
        """Create tabbed interface for results"""
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget {
                background-color: transparent;
            }
            QTabBar::tab {
                background-color: rgba(45, 25, 70, 0.5);
                color: #c084fc;
                padding: 12px 24px;
                border: 1.5px solid rgba(168, 85, 247, 0.2);
                border-radius: 10px 10px 0 0;
                margin-right: 6px;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(168, 85, 247, 0.25), stop:1 rgba(236, 72, 153, 0.15));
                color: #f472b6;
                border: 2px solid #ec4899;
            }
            QTabWidget::pane {
                border: 1.5px solid rgba(168, 85, 247, 0.2);
                border-radius: 12px;
            }
        """)

        # Overview tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 10, 40, 0.6);
                color: #a8e6cf;
                border: none;
                border-radius: 12px;
                padding: 18px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }
        """)
        overview_layout.addWidget(self.overview_text)
        tabs.addTab(overview_tab, "📊 Overview")

        # Findings tab
        findings_tab = QWidget()
        findings_layout = QVBoxLayout(findings_tab)
        self.findings_text = QTextEdit()
        self.findings_text.setReadOnly(True)
        self.findings_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 10, 40, 0.6);
                color: #fbbf24;
                border: none;
                border-radius: 12px;
                padding: 18px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }
        """)
        findings_layout.addWidget(self.findings_text)
        tabs.addTab(findings_tab, "⚠️ Findings")

        # Mitigations tab
        mitigations_tab = QWidget()
        mitigations_layout = QVBoxLayout(mitigations_tab)
        self.mitigations_text = QTextEdit()
        self.mitigations_text.setReadOnly(True)
        self.mitigations_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 10, 40, 0.6);
                color: #86efac;
                border: none;
                border-radius: 12px;
                padding: 18px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }
        """)
        mitigations_layout.addWidget(self.mitigations_text)
        tabs.addTab(mitigations_tab, "🛡️ Mitigations")

        # Raw Data tab
        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 10, 40, 0.6);
                color: #d1d5db;
                border: none;
                border-radius: 12px;
                padding: 18px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 10px;
            }
        """)
        raw_layout.addWidget(self.raw_text)
        tabs.addTab(raw_tab, "📋 Raw Data")

        return tabs

    def start_scan(self):
        """Start the network analysis scan"""
        target = self.ip_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP address")
            return

        # Build port list
        try:
            port_start = self.port_start.value()
            port_end = self.port_end.value()
            if port_start > port_end:
                port_start, port_end = port_end, port_start
            ports = list(range(port_start, port_end + 1))
        except:
            ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

        # Disable button and show progress
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(0)
        self.status_label.setText(f"⏳ Scanning {target}...")

        # Clear previous results
        self.overview_text.setText("")
        self.findings_text.setText("")
        self.mitigations_text.setText("")
        self.raw_text.setText("")

        # Start worker thread
        self.worker_thread = AnalysisWorker(target, ports)
        self.worker_thread.progress.connect(self.update_progress)
        self.worker_thread.finished.connect(self.on_scan_complete)
        self.worker_thread.error.connect(self.on_scan_error)
        self.worker_thread.start()

    def update_progress(self, message):
        """Update progress status"""
        self.status_label.setText(f"⏳ {message}")

    def on_scan_complete(self, results):
        """Handle scan completion"""
        try:
            self.current_results = results
            self.progress_bar.setVisible(False)
            self.scan_btn.setEnabled(True)

            target = results["target"]
            syn_results = results["syn_results"]
            ack_results = results["ack_results"]
            icmp_result = results["icmp_result"]
            repeat_analysis = results["repeat_analysis"]
            analysis = results["analysis"]
            score_data = results["score_data"]
            mitigations_list = results["mitigations"]

            # Overview
            overview = f"""
╔══════════════════════════════════════════════════════════════╗
║           NETWORK SECURITY ANALYSIS REPORT
╚══════════════════════════════════════════════════════════════╝

📍 TARGET INFORMATION
  IP Address: {target}
  Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 SCAN SUMMARY
  Total Ports Scanned: {len(syn_results)}
  Open Ports: {len([r for r in syn_results if r['status'] == 'open'])}
  Closed Ports: {len([r for r in syn_results if r['status'] == 'closed'])}
  Filtered Ports: {len([r for r in syn_results if r['status'] == 'filtered_or_no_response'])}

🎯 ICMP REACHABILITY
  Status: {icmp_result['status'].upper()}
  Response Time: {icmp_result.get('round_trip_ms', 'N/A')} ms

📈 RISK ASSESSMENT
  Overall Risk Score: {score_data.get('overall_score', 0):.1f}/100
  Risk Level: {score_data.get('risk_level', 'UNKNOWN')}

🖥️  OS DETECTION
  Detected OS: {repeat_analysis.get('os_guess', 'Unknown')}
  TTL Stability: {'STABLE' if repeat_analysis.get('ttl_stable') else 'VARIABLE'}
  IP ID Predictability: {'PREDICTABLE (⚠️ CRITICAL)' if repeat_analysis.get('ipid_predictable') else 'RANDOM'}

🔍 OPEN SERVICES DETECTED
"""
            open_ports_list = [r for r in syn_results if r['status'] == 'open']
            if open_ports_list:
                for port_result in open_ports_list:
                    overview += f"\n  • Port {port_result['port']:5d} - {port_result['service']:15s} (TTL: {port_result.get('ttl', 'N/A')})"
            else:
                overview += "\n  • No open ports detected"

            self.overview_text.setText(overview)

            # Findings
            findings = "🚨 SECURITY FINDINGS\n" + "="*60 + "\n\n"
            findings += "CRITICAL ISSUES:\n"
            findings_list = analysis.get("findings", [])
            if findings_list:
                for i, finding in enumerate(findings_list, 1):
                    findings += f"{i}. {finding}\n"
            else:
                findings += "No critical findings detected.\n"

            findings += "\n\nDETAILED ASSESSMENT:\n"
            detailed_assessment = analysis.get("detailed_assessment", "No detailed assessment available")
            if isinstance(detailed_assessment, list):
                findings += "\n".join(detailed_assessment)
            else:
                findings += str(detailed_assessment)

            findings += "\n\nRISK SUMMARY:\n"
            risk_summary = analysis.get("risk_summary", "No risk summary available")
            if isinstance(risk_summary, list):
                findings += "\n".join(risk_summary)
            else:
                findings += str(risk_summary)

            self.findings_text.setText(findings)

            # Mitigations
            mitigations_text = "🛡️  RECOMMENDED MITIGATIONS\n" + "="*60 + "\n\n"
            if mitigations_list:
                for i, mitigation in enumerate(mitigations_list, 1):
                    mitigations_text += f"{i}. {mitigation}\n"
            else:
                mitigations_text += "No mitigations available.\n"

            self.mitigations_text.setText(mitigations_text)

            # Raw Data - safely serialize
            try:
                raw_data = {
                    "summary": {
                        "target": target,
                        "open_ports": [r["port"] for r in syn_results if r["status"] == "open"],
                        "risk_score": score_data.get("overall_score"),
                        "risk_level": score_data.get("risk_level"),
                        "scan_time": datetime.now().isoformat()
                    },
                    "port_scan_results": len(syn_results),
                    "open_count": len(open_ports_list)
                }
                raw_json = json.dumps(raw_data, indent=2, default=str)
            except Exception as json_err:
                raw_json = f"Error serializing data: {str(json_err)}\n\nSummary:\n- Target: {target}\n- Open Ports: {len(open_ports_list)}\n- Risk Score: {score_data.get('overall_score', 'N/A')}"
            
            self.raw_text.setText(raw_json)

            self.status_label.setText(f"✓ Scan complete! {len(open_ports_list)} open ports found.")
            
        except Exception as e:
            self.scan_btn.setEnabled(True)
            error_msg = f"Error processing results: {str(e)}"
            self.status_label.setText(f"❌ {error_msg}")
            self.overview_text.setText(f"ERROR: {error_msg}")
            print(f"DETAILED ERROR: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()

    def on_scan_error(self, error_msg):
        """Handle scan errors"""
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"❌ Error: {error_msg}")
        QMessageBox.critical(self, "Scan Error", error_msg)

    def create_gradient_icon(self):
        """Create a gradient icon for the window"""
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        gradient = QLinearGradient(0, 0, 64, 64)
        gradient.setColorAt(0, QColor(168, 85, 247))
        gradient.setColorAt(1, QColor(236, 72, 153))
        painter.fillRect(0, 0, 64, 64, QBrush(gradient))
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Arial", 32, QFont.Weight.Bold))
        painter.drawText(8, 50, "⚡")
        painter.end()
        return QIcon(pixmap)

    def apply_theme(self):
        """Apply dark purple theme to the entire application"""
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a0f2e, stop:0.5 #16213e, stop:1 #0f3460);
            }
            QLabel {
                color: #e9d5ff;
            }
        """)


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    window = TCPIPAnalyzerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
