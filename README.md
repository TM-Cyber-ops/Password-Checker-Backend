 🛡️ Zero-Trust Cryptographic Evaluation Engine

A production-grade, decoupled full-stack cloud microservice designed to evaluate credential entropy spaces, audit character matrices, and run zero-knowledge data breach cross-referencing. Built under strict **Defense in Depth** and **Zero-Trust** security parameters.

---
### 🔗 Full-Stack Repository Navigation

🔹 **Frontend UI Repository:** [GitHub - Frontend Code Base](https://github.com/TM-Cyber-ops/Password-Checker-Frontend)

🔸 **Backend API Repository:** [GitHub - Hardened Compute Engine](https://github.com/TM-Cyber-ops/Password-Checker-Backend)

🚀 **Live Production Application:** [Launch Live Passphrase Dashboard](https://tm-cyber-ops.github.io/Password-Checker-Frontend/)




---

## 🚀 Systems Architecture Overview
This ecosystem is split into independent, decoupled infrastructure layers to prevent direct runtime manipulation of the core security loops:


*   **Frontend UI Engine**: Deployed via GitHub Pages, serving a web-optimized, responsive administrative dashboard protected by a strict Content Security Policy (`script-src 'self'`) utilizing global external event delegation.
*   **Backend Security Microservice**: Containerized and hosted via a secure Linux runtime environment on Render, handling processing logic, network firewalls, and cryptographic handshakes.
*   **Distributed State Cache**: Backed by a serverless, high-availability external Upstash Redis database cluster to isolate system memory states from local web application containers.



---

## 🔒 Hardened Security Controls

The application enforces automated data-minimization perimeters across six distinct structural layers:

*   **Network In-Transit Camouflage:** All data transit channels are encrypted via HTTPS tunnels. Payloads are obfuscated using client-side Base64 tokens at the browser boundary to blind server log proxies from raw text exposures.
*   **NIST SP 800-63B Input Sanitization:** Our boundary firewall is explicitly configured to permit the full matrix of 33 printable ASCII symbols, spaces, and punctuation operators. This eliminates user passphrase complexity barriers while preserving absolute system immunity against injection and cross-site scripting (XSS) attacks.
*   **Serverless Distributed Rate-Limiting**: Shifted away from local memory constraints and volatile network IP constraints to an anonymized, externalized **Upstash Redis Cloud** Cache Grid. The frontend automatically initializes a short-lived, randomized session token at runtime, transmitting traffic metrics via a custom (`X-Session-Token`) HTTP header. This architecture prevents mobile-carrier IP fragmentation defects, isolates true user identities from cloud database logging, and enables multi-container horizontal auto-scaling while keeping fallback proxy-aware IP walls intact against raw script bypasses.
*   **Hashed Blacklist Memory State:** The local common-word dictionary (`banned.txt`) is compiled directly into full 40-character SHA-1 mathematical tokens instantly on server boot. No plaintext password registry exists at rest within the system files.
*   **Global Hardware Memory Sanitization**: Raw bytes are handled strictly via low-level mutable data structures (`bytearray`) passed dynamically through Flask's global request context (`g`). The application completely eliminates high-level immutable text-string tracking loops. Utilizing an automated framework teardown hook (`@app.teardown_request`), the system intercepts the execution lifecycle right before connection termination. It steps through the allocated memory addresses and forcefully stomps absolute zero bits (`0`) directly over the physical server RAM slots, completely shredding the physical data footprint regardless of request success or system exceptions.
*   **Forensic Auditing Restrictions:** A multi-tier `RotatingFileHandler` captures system anomalies, performance telemetry, and entropy bit levels up to a 5MB storage ceiling, while strictly blocking raw credential metrics from committing to disk files.
*   **Fault-Isolated Dependency Loading:** The startup sequence features crash defense. If the local dictionary file database is corrupted or missing on boot, the script catches the exception, loads an isolated hardcoded array backup, and preserves system uptime.
*   **Cross-Origin Isolation (CORS):** Synchronous origin interception prevents third-party malicious scripts or unauthorized external domains from scraping or hijacking your raw backend API endpoints.
*   **Algorithmic Matrix Short-Circuiting:** Blacklisted strings are dropped at the perimeter. This prevents automated attackers from launching a CPU exhaustion denial of service by forcing the server to calculate zxcvbn patterns on strings already rejected.



---

## ⚙️ Core Algorithmic Specifications

*   **NIST SHA-1 Specifications:** Leverages standard cryptographic hashing protocols to generate anonymized mathematical tokens.
*   **k-Anonymity Privacy Pipeline:** API network checks to the global *Have I Been Pwned* registry utilize a 5-character hash prefix slice. The full string or full hash of the user's password never exits the isolated microservice perimeter.
*   **zxcvbn Heuristic Framework**: Evaluates spatial keyboard walks, sequential runs, repeat sequences, and dictionary matches across 4 independent real-time cracking scenarios, providing dynamic multi-velocity vector profiling (from Throttled Online Portals to Offline GPU Hardware Clusters).
*   **Serverless Redis State Clustering**: Utilizes memory-optimized data structures inside a serverless Upstash instance to execute real-time, low-latency sliding window IP tracking with absolute zero infrastructure maintenance overhead.
*   **Production WSGI Concurrency**: Enforces a single-worker, 3-threaded asymmetric *gthread* execution engine to handle real-time concurrent user spikes on resource-constrained cloud nodes without inflating the system's physical RAM footprint.



---

## 🛠️ Technology Stack & Optimization

*   **Frontend Footprint**: ~25.93 KB in code (HTML5, CSS3 Custom CSS Grid, Asynchronous Vanilla JavaScript, Asset-Free Layout Camouflage)
*   **Backend Footprint**: ~9.72 KB in code runtime package size (Python, Flask, Flask-CORS, Flask-Limiter, Upstash Redis, Gunicorn WSGI Container, zxcvbn-python)
*   **Performance Engine**: High-performance Python set tracking loops combined with remote Redis in-memory lookup pipelines, enabling sub-millisecond local match times and elastic horizontal scalability.

 
---

## ⚖️ License & Governance

Distributed under the MIT License. See `LICENSE` for more information.

Copyright © 2026 TM-Cyber-ops. All Rights Reserved.  
