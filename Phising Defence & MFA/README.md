# Phishing Link Defence and MFA Demo

Two separate defences for the CSCI262 phishing project:

- **Chrome extension:** checks webpage links for suspicious URL features and blocks configured domains.
- **Python MFA demo:** a local Flask login website requiring a password and a TOTP authenticator code, plus a fictional phishing page using dummy credentials.

The MFA protects the local demonstration account. It does not modify the real UOW portal or add MFA to other websites.

## Requirements

- Google Chrome.
- Python 3.10 or newer with pip and venv support.
- A compatible TOTP authenticator app on your phone.
- Internet access for the initial Python dependency installation.

Keep these folders together:

```text
project/
├── README.md
├── extension/
└── mfa_demo/
```

## 1. Install the extension

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension` folder containing `manifest.json`.
4. Enable only one copy of the extension and refresh any webpages already open.
5. Find **Phishing Link Defence** in Chrome's puzzle-piece menu. Its popup shows findings and provides a **Settings** button.

In Settings, enter hostnames one per line, without `https://`, paths, ports or wildcards, then click **Save settings**.

- **Trusted references:** used for lookalike detection; they do not override other warnings.
- **Blocked domains:** prevent new page/frame navigation to listed hosts and their subdomains.

Orange outlines indicate suspicious links; red outlines indicate blocklisted links. No outline does not guarantee safety. The extension scans supported HTTP/HTTPS webpages; no Python server is needed when using it on ordinary websites.

## 2. Start the Python demo

Open a terminal in the project folder. Run the appropriate commands below once to create the environment and install dependencies.

### Windows

```powershell
cd mfa_demo
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_demo.py
```

If `py` is unavailable, use `python -m venv .venv` for the second command.

### Linux / Kali / Ubuntu

```bash
cd mfa_demo
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run_demo.py
```

If venv support is missing, install your distribution's `python3-venv` package first.

Keep the terminal running. Press **Ctrl+C** to stop. On later runs, enter `mfa_demo` and run only the final command for your operating system. Both local websites start together; the port-8000 HTTP server is not needed.

## 3. Open the demo

| Page | Address |
| --- | --- |
| Guide / legitimate website | `http://localhost:5000` |
| Simulated inbox | `http://localhost:5000/inbox` |
| Legitimate login | `http://localhost:5000/login` |
| Fictional phishing page | `http://127.0.0.1:5001/login` |

Use the exact hostnames above. Public dummy credentials:

```text
Username: student
Password: DemoPassword!2026
```

## 4. Demonstration steps

1. Log in to the legitimate website first. Scan the enrolment QR with your authenticator app, then enter its code to confirm setup.
2. Sign out. Open the simulated inbox and click the deceptive link. The extension should warn about a hostname mismatch and an IP destination. Choose **Cancel** to show prevention.
3. Click again and deliberately choose **OK**. Submit only the dummy credentials to the fictional page; it shows a password-exposure demonstration result.
4. Open a fresh Incognito session and enter the same credentials at the legitimate login. The server should require an authenticator code and deny `/dashboard` access before verification.
5. In the normal window, complete legitimate login with a **new, unused** authenticator code to show successful access.

Close existing Incognito windows before creating the separate session. Keep `localhost` and `127.0.0.1` out of the blocklist for these steps. To test hard blocking separately, add `127.0.0.1`, save and navigate afresh to the fake page, then remove the entry afterward.

## Notes

- The QR is shown only during initial enrolment. Later logins request codes from that enrolled authenticator.
- A code used for enrolment or login cannot be reused. Wait for the next code if needed; keep phone and computer time automatic.
- Pending login expires after 3 minutes. Five failed password or OTP attempts trigger a 60-second lock.
- Enrolment is saved in `mfa_demo/instance/` across restarts. Do not include that folder, `.venv/` or `__pycache__/` when sharing/submitting source.
- In a VM, install the extension in that VM's Chrome and run the Python demo there. These servers bind to loopback; another machine cannot access them using its own localhost.
- The extension flags URL indicators, not cloned page appearance. TOTP mitigates password-only reuse but not real-time OTP relay. Use only dummy credentials in this local lab.
