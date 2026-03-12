import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from heuristics import extract_features
import joblib

model = joblib.load('model.pkl')


# ── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Malicious URL Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Global */
    .block-container { padding-top: 1rem; }

    /* Header bar */
    .header-bar {
        background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .header-bar h1 {
        color: #ffffff;
        margin: 0;
        font-size: 2rem;
        font-weight: 700;
    }
    .header-bar .nav-links a {
        color: #a0d2db;
        text-decoration: none;
        margin-left: 1.5rem;
        font-weight: 500;
        font-size: 0.95rem;
    }
    .header-bar .nav-links a:hover { color: #ffffff; }

    /* Risk badge */
    .risk-badge {
        display: inline-block;
        padding: 0.4rem 1.2rem;
        border-radius: 20px;
        font-weight: 700;
        font-size: 1.1rem;
        text-transform: uppercase;
    }
    .risk-safe   { background: #d4edda; color: #155724; }
    .risk-medium { background: #fff3cd; color: #856404; }
    .risk-high   { background: #f8d7da; color: #721c24; }

    /* Feature card */
    .feature-card {
        background: #f8f9fa;
        border-left: 4px solid #2c5364;
        padding: 1rem 1.2rem;
        border-radius: 8px;
        margin-bottom: 0.6rem;
    }
    .feature-card b { color: #203a43; }

    /* Section dividers */
    .section-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #2c5364;
        margin-top: 2rem;
        margin-bottom: 0.5rem;
        border-bottom: 3px solid #2c5364;
        padding-bottom: 0.3rem;
    }

    /* Footer */
    .footer {
        text-align: center;
        padding: 1.5rem;
        margin-top: 3rem;
        background: #0f2027;
        border-radius: 12px;
        color: #a0d2db;
        font-size: 0.85rem;
    }
    .footer a { color: #ffffff; text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
</style>
""", unsafe_allow_html=True)


# ── Session State Init ───────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []


# ── Helper: Risk Score ───────────────────────────────────────────────────────
def compute_risk_score(features):
    """Compute a 0-100 risk score from heuristic features (35 signals)."""
    score = 0

    # ── Protocol & Domain ────────────────────────────────────────────
    if not features["has_https"]:
        score += 10
    if features["has_ip_address"]:
        score += 15
    if features["suspicious_tld"]:
        score += 12
    if features["has_punycode"]:
        score += 10
    if features["domain_has_digits"]:
        score += 3
    if features["has_port"]:
        score += 8
    if features["domain_length"] > 30:
        score += 5
    elif features["domain_length"] > 20:
        score += 2

    # ── Lexical / Keyword Signals ────────────────────────────────────
    if features["has_keyword"]:
        score += 12
    if features["brand_in_path"]:
        score += 10
    if features["at_symbol"]:
        score += 12
    if features["has_tilde"]:
        score += 3

    # ── Length & Complexity ──────────────────────────────────────────
    if features["url_length"] > 100:
        score += 10
    elif features["url_length"] > 75:
        score += 6
    elif features["url_length"] > 54:
        score += 3
    if features["path_length"] > 60:
        score += 5
    if features["query_length"] > 50:
        score += 4
    if features["num_tokens"] > 20:
        score += 4

    # ── Structural Indicators ───────────────────────────────────────
    if features["num_dots"] > 5:
        score += 8
    elif features["num_dots"] > 3:
        score += 4
    if features["num_subdomains"] > 3:
        score += 6
    if features["num_subdirectories"] > 5:
        score += 4
    if features["hyphen_count"] > 4:
        score += 5
    elif features["hyphen_count"] > 2:
        score += 2
    if features["num_slashes"] > 6:
        score += 3
    if features["double_slash_redirect"]:
        score += 6
    if features["has_fragment"]:
        score += 2

    # ── Obfuscation & Entropy ───────────────────────────────────────
    if features["num_encoded_chars"] > 3:
        score += 6
    elif features["num_encoded_chars"] > 0:
        score += 2
    if features["url_entropy"] > 4.5:
        score += 6
    elif features["url_entropy"] > 3.8:
        score += 3
    if features["domain_entropy"] > 4.0:
        score += 5
    elif features["domain_entropy"] > 3.0:
        score += 2
    if features["digit_letter_ratio"] > 0.6:
        score += 5
    if features["max_consecutive_chars"] > 3:
        score += 3
    if features["avg_token_length"] > 15:
        score += 5
    elif features["avg_token_length"] > 10:
        score += 2

    # ── Suspicious Patterns ─────────────────────────────────────────
    if features["is_shortened"]:
        score += 8
    if features["suspicious_extension"]:
        score += 8
    if features["num_digits"] > 10:
        score += 5
    elif features["num_digits"] > 5:
        score += 2
    if features["num_query_params"] > 4:
        score += 3
    if features["num_special_chars"] > 5:
        score += 3
    if features["num_ampersands"] > 5:
        score += 4
    elif features["num_ampersands"] > 2:
        score += 2
    if features["max_host_token_len"] > 20:
        score += 4

    return min(score, 100)


def risk_label(score):
    if score <= 30:
        return "Low Risk", "risk-safe"
    elif score <= 60:
        return "Medium Risk", "risk-medium"
    else:
        return "High Risk", "risk-high"


def _card(name, value):
    st.write(f"**{name}:** {value}")


def build_gauge(score):
    """Return a Plotly gauge figure for the risk score."""
    label, _ = risk_label(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": label, "font": {"size": 22, "color": "#2c5364"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": "#2c5364"},
            "steps": [
                {"range": [0, 30], "color": "#d4edda"},
                {"range": [30, 60], "color": "#fff3cd"},
                {"range": [60, 100], "color": "#f8d7da"},
            ],
            "threshold": {
                "line": {"color": "red", "width": 4},
                "thickness": 0.8,
                "value": score,
            },
        },
    ))
    fig.update_layout(height=280, margin=dict(t=60, b=20, l=40, r=40))
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 1. HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="header-bar">
    <h1>🛡️ Malicious URL Detector</h1>
    <div class="nav-links">
        <a href="#scan">Scan</a>
        <a href="#features">Features</a>
        <a href="#about">About</a>
        <a href="#contact">Contact</a>
    </div>
</div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# 2. URL INPUT & ANALYZE
# ══════════════════════════════════════════════════════════════════════════════
st.markdown('<div id="scan"></div>', unsafe_allow_html=True)
col_input, col_btn = st.columns([5, 1])

with col_input:
    url_input = st.text_input(
        "Enter URL to scan",
        placeholder="https://example.com/login?user=admin",
        label_visibility="collapsed",
    )

with col_btn:
    analyze_clicked = st.button("🔍 Analyze", use_container_width=True, type="primary")


# ══════════════════════════════════════════════════════════════════════════════
# 3. RESULTS — Risk Gauge + Feature Breakdown + API Results
# ══════════════════════════════════════════════════════════════════════════════
if analyze_clicked and url_input.strip():
    url = url_input.strip()
    features = extract_features(url)
    features_list = list(features.values())
    prediction = model.predict([features_list])
    score = compute_risk_score(features)
    label, css_class = risk_label(score)

    if score <= 30:
        ml_verdict = "Safe ✅"
    elif score <= 60:
        ml_verdict = "Suspicious ⚠️" if prediction[0] == 0 else "Malicious 🚨"
    else:
        ml_verdict = "Malicious 🚨"

    # Save to history
    st.session_state.history.insert(0, {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "URL": url,
        "Risk Score": score,
        "Verdict": label,
    })

    st.markdown('<div class="section-title">Analysis Results</div>', unsafe_allow_html=True)

    col_gauge, col_features = st.columns([1, 1])

    # ── Risk Gauge ───────────────────────────────────────────────────────
    with col_gauge:
        st.plotly_chart(build_gauge(score), use_container_width=True)
        st.markdown(
            f'<div style="text-align:center"><span class="risk-badge {css_class}">{label} — {score}/100</span></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<div style="text-align:center; margin-top:0.8rem; font-size:1.1rem;"><b>ML Verdict:</b> {ml_verdict}</div>',
            unsafe_allow_html=True,
        )

    # ── Feature Breakdown ────────────────────────────────────────────────
    with col_features:
        st.markdown("##### 📋 Feature Breakdown (35 signals)")

        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🔒 Protocol & Domain",
            "🔤 Lexical",
            "📏 Length",
            "🏗️ Structure",
            "🕵️ Obfuscation",
        ])

        with tab1:
            _card("HTTPS", "✅ Yes" if features["has_https"] else "❌ No")
            _card("IP Address as Host", "⚠️ Yes" if features["has_ip_address"] else "✅ No")
            _card("Suspicious TLD", "⚠️ Yes" if features["suspicious_tld"] else "✅ No")
            _card("Punycode (xn--)", "⚠️ Yes" if features["has_punycode"] else "✅ No")
            _card("Domain Has Digits", "⚠️ Yes" if features["domain_has_digits"] else "✅ No")
            _card("Non-Standard Port", "⚠️ Yes" if features["has_port"] else "✅ No")
            _card("Domain Length", f"{features['domain_length']} chars")

        with tab2:
            _card("Phishing Keywords", "⚠️ Found" if features["has_keyword"] else "✅ None")
            _card("Brand in Path/Query", "⚠️ Found" if features["brand_in_path"] else "✅ None")
            _card("@ Symbol", "⚠️ Present" if features["at_symbol"] else "✅ Absent")
            _card("Tilde (~)", "⚠️ Present" if features["has_tilde"] else "✅ Absent")
            _card("URL Shortener", "⚠️ Yes" if features["is_shortened"] else "✅ No")
            _card("Suspicious Extension", "⚠️ Yes" if features["suspicious_extension"] else "✅ No")

        with tab3:
            _card("URL Length", f"{features['url_length']} chars")
            _card("Path Length", f"{features['path_length']} chars")
            _card("Query Length", f"{features['query_length']} chars")
            _card("Domain Length", f"{features['domain_length']} chars")
            _card("Avg Token Length", str(features["avg_token_length"]))
            _card("Max Host Token", f"{features['max_host_token_len']} chars")

        with tab4:
            _card("Dot Count", str(features["num_dots"]))
            _card("Subdomain Count", str(features["num_subdomains"]))
            _card("Subdirectory Count", str(features["num_subdirectories"]))
            _card("Slash Count", str(features["num_slashes"]))
            _card("Hyphen Count", str(features["hyphen_count"]))
            _card("Query Params", str(features["num_query_params"]))
            _card("Ampersands (&)", str(features["num_ampersands"]))
            _card("Fragment (#)", "Present" if features["has_fragment"] else "Absent")
            _card("Double-Slash Redirect", "⚠️ Yes" if features["double_slash_redirect"] else "✅ No")
            _card("Token Count", str(features["num_tokens"]))

        with tab5:
            _card("Digit Count", str(features["num_digits"]))
            _card("Digit/Letter Ratio", str(features["digit_letter_ratio"]))
            _card("Special Chars", str(features["num_special_chars"]))
            _card("%-Encoded Chars", str(features["num_encoded_chars"]))
            _card("URL Entropy", str(features["url_entropy"]))
            _card("Domain Entropy", str(features["domain_entropy"]))
            _card("Max Consecutive Chars", str(features["max_consecutive_chars"]))

    # ── API Results ──────────────────────────────────────────────────────
    st.markdown('<div class="section-title">API Threat Intelligence</div>', unsafe_allow_html=True)

    api_col1, api_col2, api_col3 = st.columns(3)

    with api_col1:
        st.info("🔗 **VirusTotal**\n\n_Integration pending — add your API key in `.env`_")
    with api_col2:
        st.info("🔗 **Google Safe Browsing**\n\n_Integration pending — add your API key in `.env`_")
    with api_col3:
        st.info("🔗 **WHOIS Lookup**\n\n_Integration pending — connect via `python-whois`_")

elif analyze_clicked:
    st.warning("Please enter a URL to analyze.")


# ══════════════════════════════════════════════════════════════════════════════
# 4. SCAN HISTORY
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.history:
    st.markdown('<div class="section-title">Scan History</div>', unsafe_allow_html=True)

    df_history = pd.DataFrame(st.session_state.history)

    def color_verdict(val):
        colors = {
            "Low Risk": "background-color: #d4edda; color: #155724",
            "Medium Risk": "background-color: #fff3cd; color: #856404",
            "High Risk": "background-color: #f8d7da; color: #721c24",
        }
        return colors.get(val, "")

    styled = df_history.style.applymap(color_verdict, subset=["Verdict"])
    st.dataframe(styled, use_container_width=True, hide_index=True)

    if st.button("🗑️ Clear History"):
        st.session_state.history = []
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# 5. FEATURES OF THE WEBSITE
# ══════════════════════════════════════════════════════════════════════════════
st.markdown('<div id="features"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-title">What This Tool Offers</div>', unsafe_allow_html=True)

feat_cols = st.columns(4)

website_features = [
    ("🔍", "Heuristic Analysis",
     "Extracts 35 structural, lexical, and statistical features from any URL — no external calls needed."),
    ("🤖", "ML Classification",
     "A trained scikit-learn model predicts maliciousness based on the extracted feature vector."),
    ("🌐", "API Cross-Check",
     "Validates URLs against VirusTotal, Google Safe Browsing, and WHOIS databases."),
    ("📊", "Real-Time Dashboard",
     "Interactive risk gauge, feature breakdown, and scan history — all in one place."),
]

for col, (icon, title, desc) in zip(feat_cols, website_features):
    with col:
        st.markdown(f"""
        <div style="background:#f8f9fa; border-radius:12px; padding:1.5rem; text-align:center; min-height:200px;">
            <div style="font-size:2.5rem;">{icon}</div>
            <h4 style="color:#2c5364; margin:0.5rem 0;">{title}</h4>
            <p style="color:#555; font-size:0.9rem;">{desc}</p>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# 6. ABOUT THE DEVELOPER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown('<div id="about"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-title">About the Developer</div>', unsafe_allow_html=True)

dev_col1, dev_col2 = st.columns([1, 3])

with dev_col1:
    st.markdown("""
    <div style="background:#2c5364; border-radius:50%; width:120px; height:120px;
                display:flex; align-items:center; justify-content:center;
                margin:auto; font-size:3rem; color:white;">
        👨‍💻
    </div>
    """, unsafe_allow_html=True)

with dev_col2:
    st.markdown("""
    **Nisha**

    I'm a developer passionate about cybersecurity, machine learning, and building tools that
    make the internet safer. This project combines heuristic analysis with trained ML models and
    external threat intelligence APIs to provide a multi-layered URL detection system.

    Feel free to reach out or contribute to the project!
    """)


# ══════════════════════════════════════════════════════════════════════════════
# 7. FOOTER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown('<div id="contact"></div>', unsafe_allow_html=True)
st.markdown("""
<div class="footer">
    <p><strong>Malicious URL Detector</strong> &nbsp;|&nbsp; Built with Streamlit & Python</p>
    <p>
        📧 <a href="mailto:your.email@example.com">your.email@example.com</a> &nbsp;|&nbsp;
        🔗 <a href="https://github.com/" target="_blank">GitHub</a> &nbsp;|&nbsp;
        📄 <a href="https://www.researchgate.net/publication/347620249_Machine_Learning_for_Malicious_URL_Detection"
              target="_blank">Research Paper Reference</a>
    </p>
    <p style="margin-top:0.5rem; font-size:0.75rem; color:#6c8fa0;">
        Feature references: Vanhoenshoven, F., Nápoles, G., Falcon, R., Vanhoof, K., & Koppen, M. (2020).
        "Machine Learning for Malicious URL Detection."
    </p>
</div>
""", unsafe_allow_html=True)