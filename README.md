# NetworkScanner
---

### MapNetwork.py

This script provides a graphical user interface (GUI) for scanning and visualizing network devices and their open ports. It uses various Python libraries such as `tkinter`, `scapy`, `networkx`, and `matplotlib` to accomplish its tasks.

#### Features:

- **Network Scanner**:
  - Automatically determines the local network range.
  - Performs ARP scanning to detect devices on the network.
  - Scans specified ports on detected devices.
  - Updates progress during port scanning.

- **Graphical User Interface (GUI)**:
  - Built with `tkinter` for user-friendly interaction.
  - Displays target network range with an option to modify it.
  - Shows scanning progress with a progress bar.
  - Outputs scan results in a scrollable text area.
  - Visualizes network devices and their connections using `networkx` and `matplotlib`.

#### Classes:

- **`NetworkScanner`**:
  - `get_network_ip()`: Determines the local network range.
  - `scan_network(target_ip)`: Performs ARP scanning to detect devices on the network.
  - `scan_ports(ip, ports, progress_callback)`: Scans specified ports on a given IP address and updates progress.

- **`NetworkScannerGUI`**:
  - `__init__(root)`: Initializes the GUI and sets up the main frame.
  - `setup_gui()`: Sets up the GUI components including frames, labels, buttons, progress bar, and output section.
  - `start_scan()`: Starts the network scan in a separate thread.
  - `update_progress(value, max_value)`: Updates the progress bar during port scanning.
  - `perform_scan(target_ip)`: Performs the network scan and port scan, updates the GUI with results, and visualizes the network graph.

#### Usage:

1. Run the script: `python MapNetwork.py`
2. The GUI window will open.
3. Modify the target network range if needed.
4. Click "Start Scan" to begin scanning the network.
5. View the scan results and network visualization in the GUI.
