# CertScope

**CertScope** is a scoped TLS certificate reconnaissance tool designed for
authorized security assessments. It enumerates hostnames and domains exposed
via SSL/TLS certificates across IP ranges while enforcing strict scope
controls.

---

## Features

- TLS certificate hostname discovery (CN & SAN)
- Cloud-safe SNI handling (AWS / Azure / GCP)
- Dual SSL backend (Python stdlib + OpenSSL fallback)
- Enforced scope guardrails
- TLS fingerprint rotation
- Stealth scanning behavior
- JSON & CSV output for reporting
- masscan API auto-detection

---

## Use Cases

- VAPT reconnaissance
- Cloud asset discovery
- Identifying forgotten or shadow services
- Mapping IP ranges to domain identities
- Certificate hygiene assessments

---

## Installation

### System Requirements
- Python 3.8+
- masscan (system binary)

```bash
sudo apt install masscan
```
### Python Env
```bash
python3 -m venv certscope-env
source certscope-env/bin/activate
pip install pyopenssl python-masscan
```

##NOTE
I made this tool as a fork of the popular tool sslScrape. This tool was made using GenAI's help.
**THIS IS FOR EDUCATIONAL PURPOSES ONLY**
```
