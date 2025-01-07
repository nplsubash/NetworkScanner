import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import socket

class NetworkScanner:
    def __init__(self):
        pass

    def get_network_ip(self):
        """Automatically determine the local network range."""
        import netifaces
        try:
            default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            iface_info = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
            ip = iface_info['addr']
            netmask = iface_info['netmask']
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            return f"{ip}/{cidr}"
        except Exception as e:
            return "Unable to detect network range"

    def scan_network(self, target_ip):
        """Perform ARP scanning to detect devices on the network."""
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        answered_list = scapy.srp(arp_request, timeout=1, verbose=False)[0]
        devices = []
        for element in answered_list:
            devices.append({
                "ip": element[1].psrc,
                "mac": element[1].hwsrc
            })
        return devices

    def scan_ports(self, ip, ports, progress_callback):
        """Scan ports on a given IP address and update progress."""
        open_ports = []
        total_ports = len(ports)
        for i, port in enumerate(ports):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            progress_callback(i + 1, total_ports)  # Update progress
        return open_ports

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("700x850")

        self.scanner = NetworkScanner()
        self.setup_gui()

    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scanning section
        scan_frame = ttk.LabelFrame(main_frame, text="Scanning", padding="10")
        scan_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)

        # Target input section
        ttk.Label(scan_frame, text="Target Network Range:").grid(row=0, column=0, sticky=tk.W)
        self.target_var = tk.StringVar(value=self.scanner.get_network_ip())
        self.target_entry = ttk.Entry(scan_frame, textvariable=self.target_var, width=30)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

        # Scan button
        self.scan_button = ttk.Button(scan_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=10)

        # Progress bar
        self.progress = ttk.Progressbar(scan_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=1, column=0, columnspan=3, pady=10)

        # Result section
        result_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        result_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)

        # Output section
        self.output_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=80, height=15)
        self.output_text.grid(row=0, column=0, columnspan=3, pady=10)

        # Graph display
        self.figure = plt.Figure(figsize=(8, 5), dpi=75)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, master=result_frame)
        self.canvas.get_tk_widget().grid(row=1, column=0, columnspan=3, pady=10)

        # Dynamic updates
        self.graph = nx.Graph()

    def start_scan(self):
        target_ip = self.target_var.get()
        self.output_text.delete(1.0, tk.END)
        self.scan_button.config(state=tk.DISABLED)
        threading.Thread(target=self.perform_scan, args=(target_ip,)).start()

    def update_progress(self, value, max_value):
        self.progress['value'] = (value / max_value) * 100
        self.root.update_idletasks()

    def perform_scan(self, target_ip):
        try:
            self.output_text.insert(tk.END, f"Scanning {target_ip}...\n")
            devices = self.scanner.scan_network(target_ip)

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "Scan Results:\n")

            self.graph.clear()
            self.graph.add_node("Network")

            total_devices = len(devices)
            for i, device in enumerate(devices, start=1):
                ip = device['ip']
                mac = device['mac']
                self.output_text.insert(tk.END, f"IP: {ip}, MAC: {mac}\n")
                self.graph.add_node(ip, mac=mac)
                self.graph.add_edge("Network", ip)

                # Perform port scan
                ports = range(20, 1025)  # Scan ports 20 to 1024
                open_ports = self.scanner.scan_ports(ip, ports, self.update_progress)
                self.output_text.insert(tk.END, f"Open Ports for {ip}: {open_ports}\n")

                # Update progress for each device
                self.update_progress(i, total_devices)

            self.ax.clear()
            nx.draw(self.graph, with_labels=True, ax=self.ax, node_color='skyblue', font_weight='bold')
            self.canvas.draw()

            if not devices:
                self.output_text.insert(tk.END, "No devices found.\n")

            # Show completion popup only after entire scan
            messagebox.showinfo("Scan Completed", f"Network scan completed.\nTotal devices found: {len(devices)}")

        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.scan_button.config(state=tk.NORMAL)
            self.progress['value'] = 0

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
