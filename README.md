# PhishGuard AI 🛡️
> A machine learning-powered phishing URL detector built for real-world cybersecurity defence.

![Python](https://img.shields.io/badge/Python-3.10-blue?style=flat-square)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-RandomForest-orange?style=flat-square)
![Streamlit](https://img.shields.io/badge/Deployed-Streamlit-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## What It Does
PhishGuard AI analyses a URL and predicts whether it is **legitimate or a phishing attempt** using a trained Random Forest classifier. It extracts structural and lexical features from the URL itself — no browsing required.

---

## Features
- 🔍 Real-time URL classification (phishing vs. legitimate)
- 🌲 Random Forest model trained on labelled phishing datasets
- 📊 Feature importance breakdown per prediction
- 🌐 Streamlit web interface — accessible from any browser
- ⚡ Lightweight — no external API calls at inference time

---

## Tech Stack
| Layer | Technology |
|---|---|
| Model | Scikit-learn (Random Forest) |
| Feature Engineering | Python (URL parsing, regex) |
| UI | Streamlit |
| Deployment | Streamlit Cloud |

---

## How It Works
1. User pastes a URL into the interface
2. The app extracts features: URL length, use of IP address, number of subdomains, presence of `@`, HTTPS usage, and more
3. The Random Forest model scores each feature and returns a prediction with confidence

---

## Run Locally
```bash
git clone https://github.com/samkiva/phishing-detector.git
cd phishing-detector
pip install -r requirements.txt
streamlit run app.py
```

---

## Project Background
Built as a portfolio piece demonstrating applied machine learning in cybersecurity. Inspired by the ethical hacking philosophy of **knowing the attack to build the defence**.

---

## Author
**Samuel Kivairu** — [@samkiva](https://github.com/samkiva)  
Statistics & Data Science | University of Nairobi  
Cybersecurity alias: **HexSentinel**

