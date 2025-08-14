# testssl-swarm.py

**Bulk Parallel SSL/TLS Protocol Scanner – Powered by [testssl.sh](https://testssl.sh/)**

`testssl-swarm.py` is a Python wrapper around the excellent open-source tool **testssl.sh** by Dirk Wetter and contributors.  
It automates scanning multiple hosts or IP addresses in parallel to quickly determine which SSL/TLS protocol versions they support.

---

## Features

- **Mass scan** a list of hosts/IPs for supported SSL/TLS protocol versions.
- Uses `testssl.sh` under the hood for accurate detection.
- **Parallel scanning** with configurable worker threads for speed.
- **Live progress bar** with the currently processed target shown in-line (no scrolling).
- Outputs results for:
  - `SSLv2`
  - `SSLv3`
  - `TLS1.0`
  - `TLS1.1`
  - `TLS1.2`
  - `TLS1.3`
- **Pass/Fail status**:
  - **Fail** if any weak protocol (`SSLv2`, `SSLv3`, `TLS1.0`, `TLS1.1`) is offered.
  - **Pass** if all weak protocols are disabled.
  - Errors or timeouts are reported as `error: ...`.
- Saves all results to a CSV file.
- Optionally dumps raw `testssl.sh` output per host for troubleshooting.

---

## Requirements

- **Python 3.6+**
- **testssl.sh** installed locally and executable  
  [Download here](https://testssl.sh/)
- **tqdm** for progress bar:
  ```bash
  pip install tqdm
