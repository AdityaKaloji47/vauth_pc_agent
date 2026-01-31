from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QFrame
)
from PySide6.QtCore import Qt, QTimer

from core.scanner import run_environment_scan
from core.usb_comm import get_usb_state, send_scan_to_vauth


# ---------------- MAIN WINDOW ----------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("VAUTH PC Agent")
        self.setFixedSize(800, 600)

        self.scan_step = 0
        self.dots = 0

        # ---------- CENTRAL WIDGET ----------
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)
        central_widget.setLayout(main_layout)

        # ---------- GLOBAL STYLE ----------
        self.setStyleSheet("""
            QWidget {
                background-color: #0f172a;
                color: #e5e7eb;
                font-family: Segoe UI;
                font-size: 14px;
            }
            QLabel#Title {
                font-size: 20px;
                font-weight: bold;
                color: #38bdf8;
            }
            QLabel#Section {
                font-size: 15px;
                font-weight: bold;
                color: #94a3b8;
                margin-top: 8px;
            }
            QPushButton {
                background-color: #1e293b;
                border: 1px solid #334155;
                padding: 6px 16px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #334155;
            }
            QPushButton#Primary {
                background-color: #2563eb;
                border: none;
            }
            QPushButton#Primary:hover {
                background-color: #1d4ed8;
            }
        """)

        # ---------- TITLE ----------
        title = QLabel("VAUTH – Secure Environment Verification")
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # ---------- USB + STATUS ROW ----------
        status_row = QHBoxLayout()

        self.usb_status = QLabel("● VAUTH Device Not Connected")
        self.usb_status.setStyleSheet("color: #ef4444; font-weight: bold;")

        self.status_label = QLabel("⏺ Status: Idle")
        self.status_label.setStyleSheet("color: #fbbf24;")

        status_row.addWidget(self.usb_status)
        status_row.addStretch()
        status_row.addWidget(self.status_label)

        main_layout.addLayout(status_row)

        # ---------- INFO CARD ----------
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #020617;
                border: 1px solid #1e293b;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        card_layout = QVBoxLayout()
        card_layout.setSpacing(10)
        card.setLayout(card_layout)
        main_layout.addWidget(card)

        # ---------- LOCATION ----------
        card_layout.addWidget(self._section_label("Location"))
        self.ip_label = QLabel("⏳ IP Address: —")
        self.country_label = QLabel("⏳ Country: —")
        card_layout.addWidget(self.ip_label)
        card_layout.addWidget(self.country_label)

        # ---------- ENVIRONMENT ----------
        card_layout.addWidget(self._section_label("Environment Checks"))
        self.vpn_label = QLabel("⏳ VPN Status: —")
        self.vm_label = QLabel("⏳ VM Status: —")
        self.rdp_label = QLabel("⏳ RDP Status: —")

        card_layout.addWidget(self.vpn_label)
        card_layout.addWidget(self.vm_label)
        card_layout.addWidget(self.rdp_label)

        # ---------- FINAL VERDICT ----------
        self.trust_label = QLabel("DEVICE TRUST: NOT EVALUATED")
        self.trust_label.setAlignment(Qt.AlignCenter)
        self.trust_label.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #94a3b8; padding: 8px;"
        )
        main_layout.addWidget(self.trust_label)

        # ---------- BUTTON BAR ----------
        button_row = QHBoxLayout()
        button_row.addStretch()

        self.reset_btn = QPushButton("Reset")
        self.reset_btn.clicked.connect(self.reset_status)

        self.scan_btn = QPushButton("Run Scan")
        self.scan_btn.setObjectName("Primary")
        self.scan_btn.clicked.connect(self.start_scan)

        button_row.addWidget(self.reset_btn)
        button_row.addWidget(self.scan_btn)

        main_layout.addLayout(button_row)

        # ---------- TIMERS ----------
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self._animate_scan)

        self.usb_timer = QTimer()
        self.usb_timer.timeout.connect(self.update_usb_status)
        self.usb_timer.start(1500)

    # ---------- HELPERS ----------
    def _section_label(self, text):
        lbl = QLabel(text)
        lbl.setObjectName("Section")
        return lbl

    def set_safe(self, label: QLabel, text: str):
        label.setText(f"✔ {text}")
        label.setStyleSheet("color: #22c55e; font-weight: bold;")

    def set_risk(self, label: QLabel, text: str):
        label.setText(f"✖ {text}")
        label.setStyleSheet("color: #ef4444; font-weight: bold;")

    # ---------- USB STATUS ----------
    def update_usb_status(self):
        state = get_usb_state()

        if state["multiple_vauth"]:
            self.usb_status.setText("● USB Security Violation")
            self.usb_status.setStyleSheet("color: #ef4444; font-weight: bold;")
        elif state["unknown_usb"]:
            self.usb_status.setText("● Unknown USB Detected")
            self.usb_status.setStyleSheet("color: #f59e0b; font-weight: bold;")
        elif state["vauth_port"]:
            self.usb_status.setText("● VAUTH Device Connected")
            self.usb_status.setStyleSheet("color: #22c55e; font-weight: bold;")
        else:
            self.usb_status.setText("● VAUTH Device Not Connected")
            self.usb_status.setStyleSheet("color: #ef4444; font-weight: bold;")

    # ---------- SCAN FLOW ----------
    def start_scan(self):
        self.scan_btn.setEnabled(False)
        self.reset_btn.setEnabled(False)

        self.scan_step = 0
        self.dots = 0

        self.status_label.setText("⏳ Status: Scanning")
        self.status_label.setStyleSheet("color: #38bdf8;")

        self.scan_timer.start(500)

    def _animate_scan(self):
        self.dots = (self.dots + 1) % 4
        self.status_label.setText("⏳ Status: Scanning" + "." * self.dots)

        self.scan_step += 1
        if self.scan_step >= 5:
            self.scan_timer.stop()
            self.run_scan()

    def run_scan(self):
        result = run_environment_scan()

        # LOCATION
        loc = result["location"]
        if loc["success"]:
            self.set_safe(self.ip_label, f"IP Address: {loc['ip']}")
            self.set_safe(self.country_label, f"Country: {loc['country']}")

        # VPN
        if result["vpn"]["active"]:
            self.set_risk(self.vpn_label, "VPN Status: ACTIVE")
        else:
            self.set_safe(self.vpn_label, "VPN Status: Not detected")

        # VM
        if result["vm"]["detected"]:
            self.set_risk(self.vm_label, "VM Status: DETECTED")
        else:
            self.set_safe(self.vm_label, "VM Status: Physical machine")

        # RDP
        if result["rdp"]["detected"]:
            self.set_risk(self.rdp_label, "RDP Status: ACTIVE")
        else:
            self.set_safe(self.rdp_label, "RDP Status: Not detected")

        # FINAL VERDICT
        if result["trusted"]:
            self.trust_label.setText("✔ DEVICE TRUSTED")
            self.trust_label.setStyleSheet(
                "color: #22c55e; font-size: 17px; font-weight: bold;"
            )
            self.status_label.setText("✔ Status: Scan completed")
            self.status_label.setStyleSheet("color: #22c55e;")
        else:
            self.trust_label.setText("✖ DEVICE NOT TRUSTED")
            self.trust_label.setStyleSheet(
                "color: #ef4444; font-size: 17px; font-weight: bold;"
            )
            self.status_label.setText("✖ Status: Scan completed with risks")
            self.status_label.setStyleSheet("color: #ef4444;")

        self.scan_btn.setEnabled(True)
        self.reset_btn.setEnabled(True)

    # ---------- RESET ----------
    def reset_status(self):
        self.status_label.setText("⏺ Status: Idle")
        self.status_label.setStyleSheet("color: #fbbf24;")

        self.ip_label.setText("⏳ IP Address: —")
        self.country_label.setText("⏳ Country: —")
        self.vpn_label.setText("⏳ VPN Status: —")
        self.vm_label.setText("⏳ VM Status: —")
        self.rdp_label.setText("⏳ RDP Status: —")

        self.ip_label.setStyleSheet("color: #e5e7eb;")
        self.country_label.setStyleSheet("color: #e5e7eb;")
        self.vpn_label.setStyleSheet("color: #e5e7eb;")
        self.vm_label.setStyleSheet("color: #e5e7eb;")
        self.rdp_label.setStyleSheet("color: #e5e7eb;")

        self.trust_label.setText("DEVICE TRUST: NOT EVALUATED")
        self.trust_label.setStyleSheet("color: #94a3b8;")
