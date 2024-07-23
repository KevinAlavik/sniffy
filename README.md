# Sniffy: An Advanced IP Packet Sniffer

`Sniffy` is a Python-based IP packet sniffer designed to capture and analyze network packets. It provides detailed packet information, DNS query logging, and protocol-based filtering.

## Features

- **Packet Sniffing**: Captures packets from a specified network interface.
- **Logging**: Configurable logging to console or file with verbosity levels.
- **Protocol Filtering**: Filter packets by protocol (`TCP`, `UDP`, `ICMP`).
- **Custom Filters**: Apply custom Berkeley Packet Filter (BPF) expressions.
- **DNS Query Display**: Optionally logs DNS query details.
- **Detailed Packet Information**: Provides detailed logs of packet contents.

## How It Works

1. **Setup and Configuration**:
   - **Logging**: Configures logging to print messages to the console or save them to a file. Adjusts logging level based on verbosity.
   - **Dependencies**: Uses `scapy` for packet sniffing, `netifaces` for network interface details, and `loguru` for logging.

2. **Command-Line Arguments**:
   - **Arguments Parsing**: Uses `argparse` to handle command-line inputs like the target IP address, network interface, and filters.

3. **Network Interface Setup**:
   - **Local IP Retrieval**: Identifies the local IP address of the specified network interface.

4. **Packet Sniffing**:
   - **Capture Packets**: Uses `scapy` to listen to packets on the network. Applies filters based on user input to focus on relevant packets.

5. **Packet Processing**:
   - **Filter Packets**: Checks if packets match the target IP address and logs information about them.
   - **Log Details**: Logs basic packet information such as source, destination, and protocol. If verbose mode is enabled, logs detailed packet contents including TCP/UDP headers and DNS queries.

6. **Error Handling**:
   - **Error Logging**: Catches and logs errors to handle issues during execution.

## Installation and Setup

### Prerequisites

1. **Python 3.7+**: Ensure Python 3.7 or newer is installed.
2. **Administrative Privileges**: Running `Sniffy` requires elevated permissions to access network interfaces.

### Setting Up the Environment

1. **Clone the Repository**

   ```bash
   git clone https://github.com/KevinAlavik/sniffy.git
   cd sniffy
   ```

2. **Create a Virtual Environment**

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**

   Create a `requirements.txt` file with:

   ```plaintext
   scapy
   netifaces
   loguru
   ```

   Install with:

   ```bash
   pip install -r requirements.txt
   ```

### Running Sniffy

`Sniffy` requires `sudo` or administrative rights. Run the script with elevated permissions:

```bash
sudo python sniffy.py <target_ip> [options]
```

### Command-Line Arguments

- `target_ip`: IP address of the target to sniff.
- `--interface`: Network interface to use.
- `--verbose`: Enable detailed logging.
- `--timeout`: Time to sniff (default: 60 seconds).
- `--filter`: Custom BPF filter (e.g., `tcp`, `udp`, `port 80`).
- `--logfile`: File for logs (optional).
- `--show-dns`: Log DNS query details.
- `--packet-count`: Number of packets to capture (default: unlimited).
- `--protocol`: Filter by protocol (`tcp`, `udp`, `icmp`).

### Example Usage

```bash
sudo python sniffy.py 10.0.0.1 --interface wlan0 --verbose --filter "tcp and port 443" --logfile sniffy.log --timeout 120 --show-dns
```

In this example, the script captures TCP packets on port 443, logs to `sniffy.log`, runs for 120 seconds, and includes DNS details.

## Troubleshooting

- **Permissions**: Use `sudo` to ensure you have the necessary permissions for sniffing.
- **Dependencies**: If you encounter issues, recreate the virtual environment and reinstall dependencies.

Feel free to reach out if you have any questions or need further assistance. Enjoy using `Sniffy` for your packet sniffing needs!