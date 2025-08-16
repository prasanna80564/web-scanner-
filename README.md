
WebSecGuard 🔒
A lightweight browser extension for real-time detection of XSS and CSRF vulnerabilities
📖 Overview
WebSecGuard is a browser extension designed to enhance web application security by detecting and alerting users to potential Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) attacks.
It monitors DOM manipulations and HTTP requests to identify malicious activity, providing real-time alerts directly in the browser.
This project was developed as part of a dissertation on browser-based security solutions.
✨ Features
✅ Real-time detection of XSS payloads (DOM injections, script events, malicious attributes).
✅ CSRF protection awareness by monitoring requests for missing or invalid tokens.
✅ Lightweight architecture built using Manifest V3.
✅ User-friendly alerts via notifications and popup interface.
✅ Logging & reporting of detected vulnerabilities for later review.
🏗️ Architecture
Manifest.json – defines permissions, content scripts, and background service worker.
Content Scripts – monitor DOM and form submissions for suspicious patterns.
Background Script – manages storage, notifications, and vulnerability logging.
Popup UI – displays detected vulnerabilities and allows user control.
📸 Screenshots
(Add images of your extension here – popup UI, detection alerts, vulnerability list)
🚀 Installation
Clone this repository:
git clone https://github.com/your-username/WebSecGuard.git
Open Chrome (or any Chromium-based browser) and go to:
chrome://extensions/
Enable Developer Mode (top-right).
Click Load unpacked and select the project folder.
The extension will appear in your toolbar 🎉.
🧪 Testing
This project was evaluated using:
PortSwigger Web Security Academy
Simulated XSS & CSRF attack labs in safe, controlled environments.
To test yourself:
Load the extension.
Visit any XSS/CSRF lab environment.
Trigger an attack vector and observe WebSecGuard’s detection alert.
⚠️ Disclaimer
This extension is intended for educational and research purposes only.
Do NOT use it to test unauthorized systems. Always practice ethical security testing.
📌 Future Work
Extend detection to additional vulnerabilities (SQL Injection, Clickjacking).
Incorporate machine learning for adaptive detection of novel attacks.
Expand cross-browser support beyond Chromium.
