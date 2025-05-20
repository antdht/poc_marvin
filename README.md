# Bleichenbacher Attack PoC – INFO-F514

This repository contains a **proof of concept** (PoC) for the **Bleichenbacher attack**, implemented as part of the INFO-F514 course project.

The Bleichenbacher attack targets RSA encryption implementations that are vulnerable to **padding oracle attacks**, allowing attackers to decrypt ciphertexts without access to the private key. This PoC demonstrates the feasibility of such an attack targetting the python library `pyca/cryptography` in version 3.1.1.

The project was originally intended to demonstrate a Marvin attack, a modern variation of Bleichenbacher's padding oracle attack that leverages side-channel information (such as timing differences). However, due to the time constraints and the complexity of implementing accurate side-channel measurements, the focus was shifted to a more classic Bleichenbacher approach using a simulated padding oracle.

## Authors

* **Bajraktari Eron** (516414)
* **Dhainaut Antoine** (525982)
* **Dupret Alexis** (586999)
* **Etienne Charles** (616670)
* **Pierret Valentin** (610133)

## Project Structure

```
poc-marvin/
├── src/                  # Source code of the attack
├── requirements.txt      # Python dependencies
├── README.md             
└── ...
```

## Setup Instructions

To run this project locally, we recommend using a Python virtual environment to manage dependencies cleanly.

### 2. Create and Activate a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # On Linux/macOS
# OR
.venv\Scripts\activate           # On Windows
```

### 3. Install Dependencies

Install all required Python libraries using the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 4. Run the PoC

Navigate to the `src/` directory and run the main attack script:

```bash
python main.py
```
