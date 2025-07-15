import sys
import socket
import threading
import time
import json
import platform
import subprocess
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import psutil
import scapy.all as scapy
from collections import defaultdict
import pandas as pd
import numpy as np
import pythonping
import dns.resolver

# Telegram Bot Configuration
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"

# Global variables
monitoring_active = False
monitored_ip = ""
threat_data = {
    "dos_attempts": 0,
    "ddos_attempts": 0,
    "port_scans": 0,
    "unusual_traffic": 0,
    "total_threats": 0
}
network_stats = defaultdict(int)
packet_counts = defaultdict(int)
ip_traffic = defaultdict(int)

class CyberGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Network Threats Simulator Gui")
        self.root.geometry("1200x800")
        self.set_theme()
        
        # Initialize components
        self.create_menu()
        self.create_main_frame()
        self.create_terminal()
        self.create_dashboard()
        self.create_visualization_frame()
        
        # Start background monitoring thread
        self.monitoring_thread = None
        self.packet_thread = None
        
        # Initialize Telegram bot
        self.telegram_bot = TelegramBot(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)
        
    def set_theme(self):
        """Set the green and black theme"""
        self.root.configure(bg='black')
        style = ttk.Style()
        style.theme_use('alt')
        
        # Configure styles
        style.configure('TFrame', background='black')
        style.configure('TLabel', background='black', foreground='green')
        style.configure('TButton', background='black', foreground='green')
        style.configure('TEntry', fieldbackground='black', foreground='green')
        style.configure('TText', background='black', foreground='green')
        style.configure('TScrollbar', background='black')
        style.configure('TMenubutton', background='black', foreground='green')
        style.configure('TMenu', background='black', foreground='green')
        style.configure('Treeview', background='black', foreground='green', fieldbackground='black')
        style.configure('Treeview.Heading', background='black', foreground='green')
        style.map('Treeview', background=[('selected', 'dark green')])
        
    def create_menu(self):
        """Create the main menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Monitoring", command=self.new_monitoring)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        tools_menu.add_command(label="Threat Analyzer", command=self.open_threat_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Terminal", command=self.show_terminal)
        view_menu.add_command(label="Visualizations", command=self.show_visualizations)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Telegram Settings", command=self.open_telegram_settings)
        settings_menu.add_command(label="Theme Settings", command=self.change_theme)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_main_frame(self):
        """Create the main frame with IP input and monitoring controls"""
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # IP Address Entry
        ip_frame = ttk.Frame(self.main_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ip_frame, text="Target IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Monitoring Controls
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(control_frame, text="Export Data", command=self.export_data)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(self.main_frame, textvariable=self.status_var).pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_terminal(self):
        """Create the terminal emulator frame"""
        self.terminal_frame = ttk.Frame(self.main_frame)
        
        # Terminal Output
        self.terminal_output = tk.Text(self.terminal_frame, height=15, wrap=tk.WORD)
        self.terminal_output.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Terminal Input
        terminal_input_frame = ttk.Frame(self.terminal_frame)
        terminal_input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(terminal_input_frame, text=">").pack(side=tk.LEFT)
        self.terminal_input = ttk.Entry(terminal_input_frame)
        self.terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind("<Return>", self.process_terminal_command)
        
        # Help label
        ttk.Label(self.terminal_frame, text="Type 'help' for available commands").pack(side=tk.BOTTOM)
    
    def create_dashboard(self):
        """Create the dashboard frame with threat statistics"""
        self.dashboard_frame = ttk.Frame(self.main_frame)
        
        # Threat Statistics
        stats_frame = ttk.LabelFrame(self.dashboard_frame, text="Threat Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create labels for each threat type
        self.dos_label = ttk.Label(stats_frame, text="DOS Attempts: 0")
        self.dos_label.pack(anchor=tk.W, padx=5, pady=2)
        
        self.ddos_label = ttk.Label(stats_frame, text="DDOS Attempts: 0")
        self.ddos_label.pack(anchor=tk.W, padx=5, pady=2)
        
        self.port_scan_label = ttk.Label(stats_frame, text="Port Scans: 0")
        self.port_scan_label.pack(anchor=tk.W, padx=5, pady=2)
        
        self.unusual_traffic_label = ttk.Label(stats_frame, text="Unusual Traffic: 0")
        self.unusual_traffic_label.pack(anchor=tk.W, padx=5, pady=2)
        
        self.total_threats_label = ttk.Label(stats_frame, text="Total Threats Detected: 0")
        self.total_threats_label.pack(anchor=tk.W, padx=5, pady=2)
        
        # Network Information
        net_frame = ttk.LabelFrame(self.dashboard_frame, text="Network Information")
        net_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.network_info = tk.Text(net_frame, height=10, wrap=tk.WORD)
        self.network_info.pack(fill=tk.BOTH, expand=True)
        
        # Update network info
        self.update_network_info()
    
    def create_visualization_frame(self):
        """Create the frame for data visualizations"""
        self.visualization_frame = ttk.Frame(self.main_frame)
        
        # Create figure for plots
        self.figure, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 4))
        self.figure.patch.set_facecolor('black')
        
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('black')
            ax.tick_params(colors='green')
            for spine in ax.spines.values():
                spine.set_color('green')
        
        # Embed matplotlib figure in Tkinter
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.visualization_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Update plots with initial data
        self.update_visualizations()
    
    def show_terminal(self):
        """Show the terminal frame"""
        self.hide_all_frames()
        self.terminal_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_dashboard(self):
        """Show the dashboard frame"""
        self.hide_all_frames()
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_visualizations(self):
        """Show the visualizations frame"""
        self.hide_all_frames()
        self.visualization_frame.pack(fill=tk.BOTH, expand=True)
    
    def hide_all_frames(self):
        """Hide all content frames"""
        for frame in [self.terminal_frame, self.dashboard_frame, self.visualization_frame]:
            frame.pack_forget()
    
    def update_network_info(self):
        """Update network information display"""
        try:
            interfaces = psutil.net_if_addrs()
            info = "Network Interfaces:\n"
            
            for interface, addrs in interfaces.items():
                info += f"\nInterface: {interface}\n"
                for addr in addrs:
                    info += f"  {addr.family.name}: {addr.address}\n"
            
            self.network_info.delete(1.0, tk.END)
            self.network_info.insert(tk.END, info)
        except Exception as e:
            self.log_to_terminal(f"Error updating network info: {str(e)}")
    
    def update_threat_stats(self):
        """Update the threat statistics display"""
        self.dos_label.config(text=f"DOS Attempts: {threat_data['dos_attempts']}")
        self.ddos_label.config(text=f"DDOS Attempts: {threat_data['ddos_attempts']}")
        self.port_scan_label.config(text=f"Port Scans: {threat_data['port_scans']}")
        self.unusual_traffic_label.config(text=f"Unusual Traffic: {threat_data['unusual_traffic']}")
        self.total_threats_label.config(text=f"Total Threats Detected: {threat_data['total_threats']}")
    
    def update_visualizations(self):
        """Update the data visualizations"""
        try:
            # Clear previous plots
            self.ax1.clear()
            self.ax2.clear()
            
            # Prepare data for visualization
            labels = ['DOS', 'DDOS', 'Port Scans', 'Unusual Traffic']
            values = [
                threat_data['dos_attempts'],
                threat_data['ddos_attempts'],
                threat_data['port_scans'],
                threat_data['unusual_traffic']
            ]
            
            # Bar chart
            self.ax1.bar(labels, values, color=['red', 'orange', 'yellow', 'purple'])
            self.ax1.set_title('Threat Distribution', color='green')
            self.ax1.set_ylabel('Count', color='green')
            
            # Pie chart
            self.ax2.pie(values, labels=labels, autopct='%1.1f%%', 
                         colors=['red', 'orange', 'yellow', 'purple'])
            self.ax2.set_title('Threat Percentage', color='green')
            
            # Redraw canvas
            self.canvas.draw()
        except Exception as e:
            self.log_to_terminal(f"Error updating visualizations: {str(e)}")
    
    def log_to_terminal(self, message):
        """Log a message to the terminal output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.terminal_output.insert(tk.END, f"[{timestamp}] {message}\n")
        self.terminal_output.see(tk.END)
    
    def process_terminal_command(self, event=None):
        """Process commands entered in the terminal"""
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        self.log_to_terminal(f"> {command}")
        
        try:
            if command.lower() == "help":
                self.show_help()
            elif command.lower().startswith("ping"):
                self.ping_command(command)
            elif command.lower().startswith("tracert"):
                self.tracert_command(command)
            elif command.lower().startswith("start monitoring"):
                self.start_monitoring_command(command)
            elif command.lower() == "stop":
                self.stop_monitoring()
            elif command.lower() == "view":
                self.view_command()
            elif command.lower() == "export":
                self.export_data()
            elif command.lower().startswith("netstat"):
                self.netstat_command(command)
            elif command.lower().startswith("nslookup"):
                self.nslookup_command(command)
            elif command.lower() == "ifconfig /all":
                self.ifconfig_command(all_info=True)
            elif command.lower() == "ifconfig":
                self.ifconfig_command(all_info=False)
            else:
                self.log_to_terminal(f"Unknown command: {command}. Type 'help' for available commands.")
        except Exception as e:
            self.log_to_terminal(f"Error executing command: {str(e)}")
    
    def ping_command(self, command):
        """Execute ping command"""
        parts = command.split()
        if len(parts) < 2:
            self.log_to_terminal("Usage: ping <ip_address>")
            return
        
        ip = parts[1]
        self.log_to_terminal(f"Pinging {ip}...")
        
        try:
            response = pythonping.ping(ip, count=4)
            self.log_to_terminal(str(response))
        except Exception as e:
            self.log_to_terminal(f"Ping failed: {str(e)}")
    
    def tracert_command(self, command):
        """Execute traceroute command"""
        parts = command.split()
        if len(parts) < 2:
            self.log_to_terminal("Usage: tracert <ip_address>")
            return
        
        ip = parts[1]
        self.log_to_terminal(f"Tracing route to {ip}...")
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['tracert', ip], capture_output=True, text=True)
            else:
                result = subprocess.run(['traceroute', ip], capture_output=True, text=True)
            
            self.log_to_terminal(result.stdout)
        except Exception as e:
            self.log_to_terminal(f"Traceroute failed: {str(e)}")
    
    def start_monitoring_command(self, command):
        """Start monitoring an IP from terminal command"""
        parts = command.split()
        if len(parts) < 3:
            self.log_to_terminal("Usage: start monitoring <ip_address>")
            return
        
        ip = parts[2]
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip)
        self.start_monitoring()
    
    def view_command(self):
        """Display current threat statistics"""
        self.log_to_terminal("\nCurrent Threat Statistics:")
        self.log_to_terminal(f"DOS Attempts: {threat_data['dos_attempts']}")
        self.log_to_terminal(f"DDOS Attempts: {threat_data['ddos_attempts']}")
        self.log_to_terminal(f"Port Scans: {threat_data['port_scans']}")
        self.log_to_terminal(f"Unusual Traffic: {threat_data['unusual_traffic']}")
        self.log_to_terminal(f"Total Threats Detected: {threat_data['total_threats']}")
    
    def netstat_command(self, command):
        """Execute netstat command"""
        args = command.split()[1:] if len(command.split()) > 1 else []
        
        try:
            result = subprocess.run(['netstat'] + args, capture_output=True, text=True)
            self.log_to_terminal(result.stdout)
        except Exception as e:
            self.log_to_terminal(f"Netstat failed: {str(e)}")
    
    def nslookup_command(self, command):
        """Execute nslookup command"""
        parts = command.split()
        if len(parts) < 2:
            self.log_to_terminal("Usage: nslookup <domain>")
            return
        
        domain = parts[1]
        self.log_to_terminal(f"Resolving {domain}...")
        
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                self.log_to_terminal(f"{domain} has address {rdata.address}")
        except Exception as e:
            self.log_to_terminal(f"DNS resolution failed: {str(e)}")
    
    def ifconfig_command(self, all_info=False):
        """Display network interface information"""
        try:
            interfaces = psutil.net_if_addrs()
            self.log_to_terminal("\nNetwork Interfaces:")
            
            for interface, addrs in interfaces.items():
                self.log_to_terminal(f"\nInterface: {interface}")
                for addr in addrs:
                    if all_info or addr.family == socket.AF_INET:
                        self.log_to_terminal(f"  {addr.family.name}: {addr.address}")
        except Exception as e:
            self.log_to_terminal(f"Error getting interface info: {str(e)}")
    
    def show_help(self):
        """Display help information"""
        help_text = """
Available Commands:
  ping <ip_address>        - Ping an IP address
  tracert <ip_address>    - Trace route to an IP address
  start monitoring <ip>   - Start monitoring an IP address
  stop                    - Stop monitoring
  view                    - View current threat statistics
  export                  - Export threat data
  netstat [options]       - Display network statistics
  nslookup <domain>       - DNS lookup for a domain
  ifconfig                - Display basic network interface info
  ifconfig /all           - Display detailed network interface info
  help                    - Show this help message
"""
        self.log_to_terminal(help_text)
    
    def start_monitoring(self):
        """Start monitoring the specified IP address"""
        global monitoring_active, monitored_ip
        
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address to monitor")
            return
        
        try:
            socket.inet_aton(ip)  # Validate IP address
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        if monitoring_active:
            messagebox.showwarning("Warning", "Monitoring is already active")
            return
        
        monitored_ip = ip
        monitoring_active = True
        
        # Start monitoring threads
        self.monitoring_thread = threading.Thread(target=self.monitor_threats, daemon=True)
        self.monitoring_thread.start()
        
        self.packet_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.packet_thread.start()
        
        # Update UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Monitoring {ip}...")
        
        self.log_to_terminal(f"Started monitoring {ip}")
        
        # Send Telegram notification
        self.telegram_bot.send_message(f"🚨 Accurate Cyber Defense Bot Simulatoring {ip}")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        global monitoring_active
        
        if not monitoring_active:
            messagebox.showwarning("Warning", "Monitoring is not active")
            return
        
        monitoring_active = False
        
        # Wait for threads to finish
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2)
        
        if self.packet_thread and self.packet_thread.is_alive():
            self.packet_thread.join(timeout=2)
        
        # Update UI
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Monitoring stopped")
        
        self.log_to_terminal("Stopped monitoring")
        
        # Send Telegram notification
        self.telegram_bot.send_message("🛑 Accurate monitoring")
    
    def monitor_threats(self):
        """Monitor for various threats"""
        global threat_data
        
        self.log_to_terminal("Threat monitoring started")
        
        while monitoring_active:
            try:
                # Simulate threat detection (in a real tool, this would analyze actual network traffic)
                time.sleep(5)
                
                # Randomly detect some threats for demonstration
                if monitored_ip:  # Only if we're monitoring an IP
                    current_time = datetime.now().strftime("%H:%M:%S")
                    
                    # Detect some random threats
                    if np.random.random() < 0.2:
                        threat_data['dos_attempts'] += 1
                        threat_data['total_threats'] += 1
                        self.log_to_terminal(f"[{current_time}] Detected DOS attempt on {monitored_ip}")
                        self.telegram_bot.send_message(f"⚠️ Detected DOS attempt on {monitored_ip}")
                    
                    if np.random.random() < 0.1:
                        threat_data['ddos_attempts'] += 1
                        threat_data['total_threats'] += 1
                        self.log_to_terminal(f"[{current_time}] Detected DDOS attempt on {monitored_ip}")
                        self.telegram_bot.send_message(f"⚠️ Detected DDOS attempt on {monitored_ip}")
                    
                    if np.random.random() < 0.3:
                        threat_data['port_scans'] += 1
                        threat_data['total_threats'] += 1
                        self.log_to_terminal(f"[{current_time}] Detected port scan on {monitored_ip}")
                        self.telegram_bot.send_message(f"⚠️ Detected port scan on {monitored_ip}")
                    
                    if np.random.random() < 0.4:
                        threat_data['unusual_traffic'] += 1
                        threat_data['total_threats'] += 1
                        self.log_to_terminal(f"[{current_time}] Detected unusual traffic from {monitored_ip}")
                        self.telegram_bot.send_message(f"⚠️ Detected unusual traffic from {monitored_ip}")
                    
                    # Update UI
                    self.update_threat_stats()
                    self.update_visualizations()
                
            except Exception as e:
                self.log_to_terminal(f"Error in threat monitoring: {str(e)}")
                time.sleep(5)  # Prevent rapid error loops
    
    def capture_packets(self):
        """Capture and analyze network packets"""
        self.log_to_terminal("Packet capture started")
        
        def packet_handler(packet):
            if not monitoring_active:
                return
            
            try:
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    
                    # Count packets per protocol
                    if packet.haslayer(scapy.TCP):
                        network_stats['tcp'] += 1
                    elif packet.haslayer(scapy.UDP):
                        network_stats['udp'] += 1
                    elif packet.haslayer(scapy.ICMP):
                        network_stats['icmp'] += 1
                    else:
                        network_stats['other'] += 1
                    
                    # Track traffic to/from monitored IP
                    if monitored_ip in (src_ip, dst_ip):
                        ip_traffic[monitored_ip] += 1
                        
                        # Detect potential threats
                        if packet.haslayer(scapy.TCP):
                            tcp = packet[scapy.TCP]
                            
                            # Detect port scans (SYN packets to multiple ports)
                            if tcp.flags == 'S':  # SYN flag
                                packet_counts[(src_ip, dst_ip, tcp.dport)] += 1
                                
                                if packet_counts[(src_ip, dst_ip, tcp.dport)] > 3:
                                    current_time = datetime.now().strftime("%H:%M:%S")
                                    self.log_to_terminal(f"[{current_time}] Potential port scan detected from {src_ip}")
                                    self.telegram_bot.send_message(f"⚠️ Potential port scan detected from {src_ip}")
                                    threat_data['port_scans'] += 1
                                    threat_data['total_threats'] += 1
                                    self.update_threat_stats()
                                    self.update_visualizations()
            
            except Exception as e:
                self.log_to_terminal(f"Error processing packet: {str(e)}")
        
        while monitoring_active:
            try:
                scapy.sniff(prn=packet_handler, store=0, count=100, timeout=5)
            except Exception as e:
                self.log_to_terminal(f"Error in packet capture: {str(e)}")
                time.sleep(5)
    
    def export_data(self):
        """Export threat data to a file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
                title="Save Threat Data"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(threat_data, f, indent=4)
                
                self.log_to_terminal(f"Threat data exported to {filename}")
                self.telegram_bot.send_message(f"📊 Threat data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def new_monitoring(self):
        """Start a new monitoring session"""
        if monitoring_active:
            if messagebox.askyesno("Confirm", "Monitoring is active. Stop current session?"):
                self.stop_monitoring()
    
    def save_session(self):
        """Save the current session"""
        session_data = {
            'monitored_ip': monitored_ip,
            'threat_data': threat_data,
            'network_stats': dict(network_stats),
            'packet_counts': dict(packet_counts),
            'ip_traffic': dict(ip_traffic)
        }
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".cg",
                filetypes=[("CyberGuard Sessions", "*.cg"), ("All Files", "*.*")],
                title="Save Session"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(session_data, f)
                
                self.log_to_terminal(f"Session saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save session: {str(e)}")
    
    def load_session(self):
        """Load a saved session"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("CyberGuard Sessions", "*.cg"), ("All Files", "*.*")],
                title="Load Session"
            )
            
            if filename:
                with open(filename, 'r') as f:
                    session_data = json.load(f)
                
                global monitored_ip, threat_data, network_stats, packet_counts, ip_traffic
                
                monitored_ip = session_data.get('monitored_ip', "")
                threat_data = session_data.get('threat_data', {
                    "dos_attempts": 0,
                    "ddos_attempts": 0,
                    "port_scans": 0,
                    "unusual_traffic": 0,
                    "total_threats": 0
                })
                
                network_stats = defaultdict(int, session_data.get('network_stats', {}))
                packet_counts = defaultdict(int, session_data.get('packet_counts', {}))
                ip_traffic = defaultdict(int, session_data.get('ip_traffic', {}))
                
                # Update UI
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, monitored_ip)
                
                self.update_threat_stats()
                self.update_visualizations()
                
                self.log_to_terminal(f"Session loaded from {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load session: {str(e)}")
    
    def open_network_scanner(self):
        """Open the network scanner tool"""
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("Network Scanner")
        scanner_window.geometry("600x400")
        
        # Add scanner functionality here
        ttk.Label(scanner_window, text="Network Scanner (Under Development)").pack(pady=20)
    
    def open_packet_analyzer(self):
        """Open the packet analyzer tool"""
        analyzer_window = tk.Toplevel(self.root)
        analyzer_window.title("Packet Analyzer")
        analyzer_window.geometry("600x400")
        
        # Add analyzer functionality here
        ttk.Label(analyzer_window, text="Packet Analyzer (Under Development)").pack(pady=20)
    
    def open_threat_analyzer(self):
        """Open the threat analyzer tool"""
        analyzer_window = tk.Toplevel(self.root)
        analyzer_window.title("Threat Analyzer")
        analyzer_window.geometry("600x400")
        
        # Add analyzer functionality here
        ttk.Label(analyzer_window, text="Threat Analyzer (Under Development)").pack(pady=20)
    
    def open_telegram_settings(self):
        """Open Telegram bot settings"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Telegram Settings")
        settings_window.geometry("400x300")
        
        # Add settings controls here
        ttk.Label(settings_window, text="Telegram Bot Token:").pack(pady=5)
        token_entry = ttk.Entry(settings_window, width=40)
        token_entry.pack(pady=5)
        token_entry.insert(0, TELEGRAM_TOKEN)
        
        ttk.Label(settings_window, text="Chat ID:").pack(pady=5)
        chat_id_entry = ttk.Entry(settings_window, width=40)
        chat_id_entry.pack(pady=5)
        chat_id_entry.insert(0, TELEGRAM_CHAT_ID)
        
        def save_settings():
            global TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
            TELEGRAM_TOKEN = token_entry.get()
            TELEGRAM_CHAT_ID = chat_id_entry.get()
            self.telegram_bot.update_credentials(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)
            messagebox.showinfo("Success", "Telegram settings updated")
            settings_window.destroy()
        
        ttk.Button(settings_window, text="Save", command=save_settings).pack(pady=10)
    
    def change_theme(self):
        """Change the application theme"""
        # In a real implementation, this would toggle between different themes
        messagebox.showinfo("Info", "Theme settings (Under Development)")
    
    def show_about(self):
        """Show about information"""
        about_text = """
Accurate Cyber Defense Bot Simulator
Version 10.0

A comprehensive cybersecurity tool for monitoring network threats
including DOS, DDOS, port scanning, and unusual traffic.

Developed by Ian Carter Kulani
"""
        messagebox.showinfo("About accurate", about_text)

class TelegramBot:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{self.token}/"
    
    def update_credentials(self, token, chat_id):
        """Update bot credentials"""
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{self.token}/"
    
    def send_message(self, text):
        """Send a message through Telegram bot"""
        if not self.token or not self.chat_id:
            return
        
        try:
            url = self.base_url + "sendMessage"
            data = {
                "chat_id": self.chat_id,
                "text": text
            }
            response = requests.post(url, data=data)
            return response.json()
        except Exception as e:
            print(f"Error sending Telegram message: {str(e)}")
            return None

def main():
    root = tk.Tk()
    app = CyberGuard(root)
    root.mainloop()

if __name__ == "__main__":
    main()