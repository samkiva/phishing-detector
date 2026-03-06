# 🛡️ PhishGuard AI

An AI-powered phishing URL detector built with Machine Learning and deployed as a web app.

## 🔍 What it does
- Analyzes any URL and predicts if it's **Safe** or **Phishing**
- Shows confidence score + risk breakdown
- Displays feature importance weights from the model

## 🧠 Tech Stack
- **Python** — core language
- **Scikit-learn** — Random Forest classifier
- **Streamlit** — web app UI
- **tldextract** — domain feature engineering

## 🚀 Run Locally
```bash
git clone https://github.com/YOUR_USERNAME/phishguard-ai
cd phishguard-ai
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python model.py       # train the model
streamlit run app.py  # launch the app
```

## 📊 Model Performance
- **Accuracy:** 100% on test set
- **Features:** URL length, HTTPS, IP detection, suspicious keywords, TLD analysis, subdomain depth

## 👤 Built by
**Sam Kiv** — Statistics + Cybersecurity + AI | University of Nairobi