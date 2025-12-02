# webswak

<p align="center">
  <img src="assets/webswak.png" alt="Projektlogo" width="150"/>
</p>

**Tagline:** The WEB SWiss Army Knife – A lightweight, flexible HTTP/HTTPS server for quick deployments and testing.

## 📖 Description
**webswak** is a Python-based tool designed to act as a Swiss Army Knife for web serving. It allows you to quickly spin up HTTP or HTTPS servers with configurable options, automatic self-signed certificate generation, and robust TLS support. 
Ideal for **developers**, **DevOps**, and **security testing** (Pentration Testers and Red Teamers).**Start your www server with a single command:**

## ✨ Features
- HTTP and HTTPS support
- Automatic self-signed certificate generation
- Custom certificate and key support with validation
- Configurable TLS versions (TLS 1.2 and TLS 1.3)
- Bind to specific network interfaces (localhost, public IP, or 0.0.0.0 for all IF)
- Directory serving with custom root path
- Secure cipher suites
- Graceful shutdown and cleanup

## 🔧 Installation

### Clone the repository
```bash
git clone https://github.com/yourusername/webswak.git
```
then 
```bash 
cd webswak
```
### Install dependencies
```bash
pip install cryptography 
```
or
```bash
pip install -r requirements.txt
```
### Make it a system command
#### On Linux
Check if /usr/local/bin/ is inside your PATH:
```bash
echo $PATH
```
##### Fix if required. 
If missing try:
```bash
export PATH=/usr/local/bin:$PATH
```
Note: You should maybe add it to .bashrc to make it persistant

##### Move/copy the Python code to /usr/local/bin/
```bash
sudo cp webswak.py /usr/local/bin/webswak && sudo chmod +x /usr/local/bin/webswak
```
#### On Windows
**Note: Python has to be already installedon the system.**

Copy webswaks.py to a folder like `C:\PyCode` and create a webswak.cmd inside the `%PATH%` e.g., in `C:\Windows\System32\`.

**Example:**

```bash
@echo off 
cmd /k python "C:\PyCode\webswak.py" %*
```
Congrats, Done! Now it should be executable at command line by just typing **webswak**. 

## 🚀 Usage Examples
Start an HTTPS server with a self-signed certificate:
```bash
c:\>webswak

             _                      _
            | |                    | |
 _ _ _ _____| |__   ___ _ _ _ _____| |  _
| | | | ___ |  _ \ /___) | | (____ | |_/ )
| | | | ____| |_) )___ | | | / ___ |  _ (
 \___/|_____)____/(___/ \___/\_____|_| \_)
                                         v1.0 by HD0x01

[INFO] No certificate provided – generating temporary self-signed certificate...
[INFO] HTTPS enabled. Make sure to use https:// in your client.
[INFO] Starting HTTPS server on 0.0.0.0:443
[INFO] Protocol: HTTP/1.0
[INFO] TLS versions: min=TLS1.2, max=TLS1.3
[INFO] Serving directory: c:\
[INFO] Press CTRL+C to stop.
192.168.0.28 - - [02/Dec/2025 09:16:11] "GET / HTTP/1.1" 200 -
192.168.0.28 - - [02/Dec/2025 09:16:11] code 404, message File not found
192.168.0.28 - - [02/Dec/2025 09:16:11] "GET /favicon.ico HTTP/1.1" 404 -
[INFO] Keyboard interrupt received, exiting.
[INFO] Temporary certificate directory C:\Users\hnandke\AppData\Local\Temp\tmp0t2w1na0 removed.
```

Start an HTTP server on port 8080:
```bash
c:\>webswak -m http -p 8080

             _                      _
            | |                    | |
 _ _ _ _____| |__   ___ _ _ _ _____| |  _
| | | | ___ |  _ \ /___) | | (____ | |_/ )
| | | | ____| |_) )___ | | | / ___ |  _ (
 \___/|_____)____/(___/ \___/\_____|_| \_)
                                         v1.0 by HD0x01

[INFO] Starting HTTP server on 0.0.0.0:8080
[INFO] Protocol: HTTP/1.0
[INFO] Serving directory: c:\
[INFO] Press CTRL+C to stop.
192.168.0.28 - - [02/Dec/2025 09:18:56] "GET / HTTP/1.1" 200 -
192.168.0.28 - - [02/Dec/2025 09:18:56] code 404, message File not found
192.168.0.28 - - [02/Dec/2025 09:18:56] "GET /favicon.ico HTTP/1.1" 404 -
[INFO] Keyboard interrupt received, exiting.
```

Start an HTTPS server bound to localhost port 4443:
```bash
c:\>webswak -m https -b 127.0.0.1 -p 4443

             _                      _
            | |                    | |
 _ _ _ _____| |__   ___ _ _ _ _____| |  _
| | | | ___ |  _ \ /___) | | (____ | |_/ )
| | | | ____| |_) )___ | | | / ___ |  _ (
 \___/|_____)____/(___/ \___/\_____|_| \_)
                                         v1.0 by HD0x01

[INFO] No certificate provided – generating temporary self-signed certificate...
[INFO] HTTPS enabled. Make sure to use https:// in your client.
[INFO] Starting HTTPS server on 127.0.0.1:4443
[INFO] Protocol: HTTP/1.0
[INFO] TLS versions: min=TLS1.2, max=TLS1.3
[INFO] Serving directory: c:\
[INFO] Press CTRL+C to stop.
127.0.0.1 - - [02/Dec/2025 09:22:21] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [02/Dec/2025 09:22:21] code 404, message File not found
127.0.0.1 - - [02/Dec/2025 09:22:21] "GET /favicon.ico HTTP/1.1" 404 -
[INFO] Keyboard interrupt received, exiting.
[INFO] Temporary certificate directory C:\Users\hnandke\AppData\Local\Temp\tmpo0anxa_r removed.
```

Start an HTTPS server with custom cert and key:
```bash
c:\>webswak -m https -c C:\TMP\cert.pem -k C:\TMP\key.pem

             _                      _
            | |                    | |
 _ _ _ _____| |__   ___ _ _ _ _____| |  _
| | | | ___ |  _ \ /___) | | (____ | |_/ )
| | | | ____| |_) )___ | | | / ___ |  _ (
 \___/|_____)____/(___/ \___/\_____|_| \_)
                                         v1.0 by HD0x01

[INFO] HTTPS enabled. Make sure to use https:// in your client.
[INFO] Starting HTTPS server on 0.0.0.0:443
[INFO] Protocol: HTTP/1.0
[INFO] TLS versions: min=TLS1.2, max=TLS1.3
[INFO] Serving directory: c:\
[INFO] Press CTRL+C to stop.
192.168.0.28 - - [02/Dec/2025 09:27:01] "GET / HTTP/1.1" 200 -
192.168.0.28 - - [02/Dec/2025 09:27:20] "GET /TMP/ HTTP/1.1" 200 -
192.168.0.28 - - [02/Dec/2025 09:27:28] "GET /TMP/key.pem HTTP/1.1" 200 -
[INFO] Keyboard interrupt received, exiting.
```


## ⚙️ Command-line Options
| Option        | Description |
|---------------|-------------|
| `-m, --mode`  | Server mode: HTTP or HTTPS (default: HTTPS) |
| `-P, --protocol` | HTTP protocol version (default: HTTP/1.0) |
| `-d, --directory` | Root directory to serve files from |
| `-b, --bind`  | Bind address (e.g., localhost, public IP, or 0.0.0.0 for all interfaces) |
| `-p, --port`  | Port number (default: 80 for HTTP, 443 for HTTPS) |
| `-c, --cert`  | Path to SSL certificate |
| `-k, --key`   | Path to SSL private key |
| `-min, --tls-min` | Minimum TLS version (default: TLS1.2) |
| `-max, --tls-max` | Maximum TLS version (default: TLS1.3) |

## 🔒 Security Notes
- Use strong certificates and don't save them inside the Webservers path
- Don't use it for production!
- Avoid running as root/sudo unless necessary
- Validate your TLS configuration for compliance

```bash
$ sslscan 127.0.0.1:443
Version: 2.1.5
OpenSSL 3.5.4 30 Sep 2025

Connected to 127.0.0.1

Testing SSL server 127.0.0.1 on port 443 using SNI name 127.0.0.1

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   disabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Session renegotiation not supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.3 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384       
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256 
Accepted  TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256       

  Server Key Exchange Group(s):
TLSv1.3  128 bits  secp256r1 (NIST P-256)
TLSv1.3  192 bits  secp384r1 (NIST P-384)
TLSv1.3  260 bits  secp521r1 (NIST P-521)
TLSv1.3  128 bits  x25519
TLSv1.3  224 bits  x448
TLSv1.3  112 bits  ffdhe2048
TLSv1.3  128 bits  ffdhe3072

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  localhost
Altnames: DNS:localhost
Issuer:   localhost

Not valid before: Dec  2 08:33:50 2025 GMT
Not valid after:  Dec  3 08:33:50 2025 GMT

```
## 📜 License
MIT License
