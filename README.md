
# Encrypted SFTP Server with VirusTotal Integration
````markdown
This is a custom-built SFTP server built with Twisted, supporting:
- AES-encrypted file uploads
- VirusTotal scanning for malware detection
- User directory isolation
- Custom authentication with logging
- Secure key generation and storage
````
## 🚀 Features
````markdown
- 🔒 AES-128 encryption for uploaded files (CFB mode)
- 🧪 MD5 hashing of plaintext for VirusTotal query
- ☣️ Auto-deletion of files flagged as malicious
- 🧑‍💻 User-specific directories (`salma`, `celine`)
- 📁 Basic SFTP operations (upload, download, list, remove)
- 🧾 Secure password handling with login attempt logging

````



## 📦 Requirements
````markdown

- Python 3.8+
- [Twisted](https://twistedmatrix.com/)
- [cryptography](https://pypi.org/project/cryptography/)
- [vt-py (VirusTotal API)](https://pypi.org/project/vt-py/)
- [zope.interface](https://pypi.org/project/zope.interface/)

Install dependencies with:
````
```bash
pip install twisted cryptography vt-py zope.interface
````

---

## 🔧 Setup

1. Clone the repository and navigate to the project folder.
2. Set up directory structure:

```bash
mkdir -p users/salma users/celine keys
```

3. Run the server:

```bash
python sftp_server.py
```

The server will:

* Create necessary folders
* Generate RSA keys if not found
* Start listening on **port 2222**

---

## 🔑 Default Users

| Username | Password |
| -------- | -------- |
| salma    | salma    |
| celine   | celine   |

These can be updated in `sftp_server.py` under `LoggingPasswordChecker`.

---

## 🧪 VirusTotal API Key

This server uses [VirusTotal](https://virustotal.com/) to scan uploaded files.
Update your API key in:

```python
client = vt.Client('YOUR_API_KEY_HERE')
```

---

## 🔐 File Encryption

Uploaded files are:

* Encrypted with AES (IV stored at file start)
* Scanned after encryption finalization
* Removed if flagged by any antivirus engine

---

## 📂 File Structure

```
project/
│
├── users/
│   ├── salma/
│   └── celine/
│
├── keys/
│   ├── aes.key
│   ├── server.key
│   └── server.key.pub
│
├── sftp_server.py
└── README.md
```

---

## 📎 Notes

* Ensure port 2222 is open if you're connecting externally.
* Connect using any SFTP client (e.g. FileZilla, `sftp` CLI).
* Server restricts file access to per-user directories only.


