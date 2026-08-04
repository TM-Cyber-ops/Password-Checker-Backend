 🛡️ Zero-Trust Cryptographic Evaluation Engine

A production-grade, decoupled full-stack cloud microservice designed to evaluate credential entropy spaces, audit character matrices, and run zero-knowledge data breach cross-referencing. Built under strict **Defense in Depth** and **Zero-Trust** security parameters.

---

## 🚀 Systems Architecture Overview

This ecosystem is split into two independent, decoupled infrastructure layers to prevent direct runtime manipulation of the core security loops:
1. **Frontend UI Engine:** Deployed via GitHub Pages, serving a web-optimized, responsive administrative dashboard.
2. **Backend Security Microservice:** Containerized and hosted via a secure Linux runtime environment on Render, handling processing logic, firewalls, and cryptographic handshakes.

---

## 🔒 Hardened Security Controls

The application enforces automated data-minimization perimeters across six distinct structural layers:

*   **Network In-Transit Camouflage:** All data transit channels are encrypted via HTTPS tunnels. Payloads are obfuscated using client-side Base64 tokens at the browser boundary to blind server log proxies from raw text exposures.
*   **NIST SP 800-63B Input Sanitization:** Our boundary firewall is explicitly configured to permit the full matrix of 33 printable ASCII symbols, spaces, and punctuation operators. This eliminates user passphrase complexity barriers while preserving absolute system immunity against injection and cross-site scripting (XSS) attacks.
*   **Proxy-Aware Application Firewall:** Leverages an inline rate-limiting router that inspects the cloud load balancer's `X-Forwarded-For` header. This bypasses Network Address Translation (NAT) limits, selectively throttling malicious traffic up to 240 requests/min without locking out shared campus Wi-Fi users.
*   **Hashed Blacklist Memory State:** The local common-word dictionary (`banned.txt`) is compiled directly into full 40-character SHA-1 mathematical tokens instantly on server boot. No plaintext password registry exists at rest within the system files.
*   **Ephemeral RAM Lifecycle:** Raw text string processing variables function under a strict ephemeral scope. They are manually overwritten with zero-byte strings (`"0" * len`) and explicitly purged from RAM execution blocks within milliseconds of calculation completion.
*   **Forensic Auditing Restrictions:** A multi-tier `RotatingFileHandler` captures system anomalies, performance telemetry, and entropy bit levels up to a 5MB storage ceiling, while strictly blocking raw credential metrics from committing to disk files.
*   **Fault-Isolated Dependency Loading:** The startup sequence features crash defense. If the local dictionary file database is corrupted or missing on boot, the script catches the exception, loads an isolated hardcoded array backup, and preserves system uptime.
*   **Cross-Origin Isolation (CORS):** Synchronous origin interception prevents third-party malicious scripts or unauthorized external domains from scraping or hijacking your raw backend API endpoints.
*   **Algorithmic Matrix Short-Circuiting:** Blacklisted strings are dropped at the perimeter. This prevents automated attackers from launching a CPU exhaustion denial of service by forcing the server to calculate zxcvbn patterns on strings already rejected.



---

## ⚙️ Core Algorithmic Specifications

*   **NIST SHA-1 Specifications:** Leverages standard cryptographic hashing protocols to generate anonymized mathematical tokens.
*   **k-Anonymity Privacy Pipeline:** API network checks to the global *Have I Been Pwned* registry utilize a 5-character hash prefix slice. The full string or full hash of the user's password never exits the isolated microservice perimeter.
*   **zxcvbn Heuristic Framework:** Evaluates spatial keyboard walks, sequential runs, repeat sequences, and dictionary matches rather than relying on outdated character-counting metrics.

---

## 🛠️ Technology Stack & Optimization

*   **Frontend Footprint:** ~25.09 KB in code (HTML5, CSS3 Custom CSS Grid, Asynchronous Vanilla JavaScript, A Image)
*   **Backend Footprint:** ~9.70 KB in code (Python, Flask, Flask-CORS, Flask-Limiter, zxcvbn-python, local ban lsit)
*   **Performance Engine:** High-performance Python `set` tracking loops enabling sub-millisecond local match times.
 
---

## ⚖️ License & Governance

Distributed under the MIT License. See `LICENSE` for more information.

Copyright © 2026 TM-Cyber-ops. All Rights Reserved.  
