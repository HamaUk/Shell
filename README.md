A hybrid vulnerability scanner combining CVE detection with live shell identification capabilities. Built for security professionals and penetration testers.

Features

· CVE Vulnerability Scanning: Detects known vulnerabilities in WordPress, Laravel, and other popular CMS platforms
· Web Shell Detection: Identifies existing web shells on target systems
· Automated Shell Upload: Attempts to upload test shells to vulnerable endpoints
· Proxy Support: SOCKS5 proxy integration for anonymous scanning
· Multithreaded Scanning: Concurrent processing for efficient large-scale assessments
· Real-time Dashboard: GUI interface displaying live results during scanning
· Comprehensive Reporting: Outputs results to files for later analysis

Supported CVEs

· CVE-2025-26892 (WordPress Celestial Aura Theme v2.2)
· CVE-2025-1304 (WordPress NewsBlogger Theme)
· CVE-2024-3452 (Laravel Voyager)
· CVE-2024-5681 (WP File Manager Plugin)

Installation

Prerequisites

· Python 3.8 or higher
· pip package manager

Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/shadowcobra-x9.git
cd shadowcobra-x9
```

1. Install required dependencies:

```bash
pip install -r requirements.txt
```

1. Prepare your target files:

```bash
# Create targets file
echo "example.com" > targets.txt
echo "test.site" >> targets.txt

# Optional: Add proxies
echo "socks5://proxy1:port" > proxy.txt
echo "socks5://proxy2:port" >> proxy.txt
```

Usage

Basic Scanning

```bash
python shadowcobra.py
```

Advanced Options

```bash
# Silent mode with custom command and HTTPS
python shadowcobra.py --silent --cmd "id" --https

# With specific shell files
python shadowcobra.py --shell shadow.php --shell shell.php.jpg
```

Command Line Arguments

Argument Description Default
--silent Suppress output except LIVE SHELL detections False
--cmd Command to execute via shell "whoami"
--https Force HTTPS requests False
--threads Number of concurrent threads 20
--timeout Request timeout in seconds 10

File Structure

```
shadowcobra-x9/
├── shadowcobra.py      # Main scanner script
├── targets.txt         # List of target domains/IPs
├── proxy.txt           # SOCKS5 proxy list (optional)
├── shadow.php          # Example web shell
├── shell.php.jpg       # Example obfuscated web shell
├── live_shells.txt     # Output file for found shells
├── debug_shell_hits.txt # Debug information
└── README.md           # This file
```

Configuration

Edit the following variables in the script for customization:

```python
TARGETS_FILE = "targets.txt"    # Target list file
PROXY_FILE = "proxy.txt"        # Proxy list file
SHELL_FILES = ["shadow.php", "shell.php.jpg"]  # Shell files to use
THREADS = 20                    # Concurrent threads
TIMEOUT = 10                    # Request timeout
```

Output Files

· live_shells.txt: Contains URLs of verified live shells
· debug_shell_hits.txt: Debug information for shell detection

Legal Disclaimer

This tool is intended for educational purposes and authorized security testing only. The user assumes all responsibility for how they use this tool. Always ensure you have proper authorization before scanning any systems.

Contributing

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

License

This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments

· Inspired by various security tools and techniques
· Thanks to the security community for vulnerability research
· Built with Python and amazing open-source libraries

Support

For questions or issues, please open a GitHub issue or contact the development team.

---

Warning: Use responsibly and only on systems you own or have explicit permission to test. Unauthorized scanning is illegal
