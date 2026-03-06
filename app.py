import streamlit as st
import joblib
import re
import tldextract
import pandas as pd

# ── Load model ────────────────────────────────────────────────────────────────
model = joblib.load('phishing_model.pkl')
feature_names = joblib.load('feature_names.pkl')

# ── Feature extractor (same as model.py) ─────────────────────────────────────
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['domain_length'] = len(tldextract.extract(url).domain)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at'] = url.count('@')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_params'] = url.count('?') + url.count('&')
    features['num_percent'] = url.count('%')
    features['has_https'] = int(url.startswith('https'))
    features['has_ip'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    sus_words = ['login','verify','secure','update','bank',
                 'paypal','account','confirm','click','free',
                 'win','prize','claim','suspend','restore']
    features['sus_word_count'] = sum(w in url.lower() for w in sus_words)
    ext = tldextract.extract(url)
    features['subdomain_depth'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    suspicious_tlds = ['.tk','.ml','.ga','.cf','.gq','.ru','.info','.win','.net']
    features['suspicious_tld'] = int(any(url.endswith(t) or t+'/' in url for t in suspicious_tlds))
    return features

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="centered"
)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
    <h1 style='text-align:center; color:#00FF9C;'>🛡️ PhishGuard AI</h1>
    <p style='text-align:center; color:gray;'>AI-powered phishing URL detector — built by Sam Kiv</p>
    <hr>
""", unsafe_allow_html=True)

# ── Input ─────────────────────────────────────────────────────────────────────
url_input = st.text_input(
    "🔗 Paste a URL to analyze:",
    placeholder="e.g. https://secure-login.paypa1.com/verify?user=sam"
)

if st.button("🔍 Analyze URL", use_container_width=True):
    if not url_input.strip():
        st.warning("Please enter a URL first.")
    else:
        with st.spinner("Analyzing..."):
            features = extract_features(url_input.strip())
            df = pd.DataFrame([features])[feature_names]
            prediction = model.predict(df)[0]
            proba = model.predict_proba(df)[0]
            confidence = proba[prediction] * 100

        st.markdown("---")

        # ── Verdict ───────────────────────────────────────────────────────────
        if prediction == 1:
            st.error(f"🚨 **PHISHING DETECTED** — {confidence:.1f}% confidence")
            st.markdown("**This URL shows signs of a phishing attack. Do NOT visit it.**")
        else:
            st.success(f"✅ **SAFE URL** — {confidence:.1f}% confidence")
            st.markdown("**No phishing signals detected in this URL.**")

        # ── Risk Breakdown ────────────────────────────────────────────────────
        st.markdown("### 🔬 Risk Breakdown")

        col1, col2 = st.columns(2)
        with col1:
            st.metric("URL Length", features['url_length'],
                      delta="High" if features['url_length'] > 75 else "Normal",
                      delta_color="inverse")
            st.metric("Suspicious Keywords", features['sus_word_count'],
                      delta="Risky" if features['sus_word_count'] > 0 else "Clean",
                      delta_color="inverse")
            st.metric("Uses HTTPS", "Yes" if features['has_https'] else "No",
                      delta=None)

        with col2:
            st.metric("IP Address in URL", "Yes" if features['has_ip'] else "No",
                      delta="Risky" if features['has_ip'] else "Clean",
                      delta_color="inverse")
            st.metric("Suspicious TLD", "Yes" if features['suspicious_tld'] else "No",
                      delta="Risky" if features['suspicious_tld'] else "Clean",
                      delta_color="inverse")
            st.metric("Subdomain Depth", features['subdomain_depth'],
                      delta="High" if features['subdomain_depth'] > 2 else "Normal",
                      delta_color="inverse")

        # ── Feature importance bar ────────────────────────────────────────────
        st.markdown("### 📊 Feature Importance (Model Weights)")
        importance_df = pd.DataFrame({
            'Feature': feature_names,
            'Importance': model.feature_importances_
        }).sort_values('Importance', ascending=False).head(8)
        st.bar_chart(importance_df.set_index('Feature'))

        # ── Raw features expander ─────────────────────────────────────────────
        with st.expander("🧪 View raw extracted features"):
            st.json(features)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:gray; font-size:12px;'>"
    "Built by <b>Sam Kiv</b> | Statistics + Cybersecurity + AI | University of Nairobi"
    "</p>",
    unsafe_allow_html=True
)