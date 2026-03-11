# 🛡️ Malicious URL Detector

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-App-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-Charts-3F4F75?style=for-the-badge&logo=plotly&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data-150458?style=for-the-badge&logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-Compute-013243?style=for-the-badge&logo=numpy&logoColor=white)

A machine-learning-powered web app that detects malicious URLs using a **651,000+ URL dataset** ([Kaggle — Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)) and **35 heuristic features**. Classifies URLs as **benign**, **phishing**, **malware**, or **defacement** in real time.

---

## ✨ Features

- **651K+ URL Dataset** — trained on Kaggle's Malicious URLs Dataset (benign, phishing, malware, defacement)
- **35-Signal Feature Engine** — lexical, structural, statistical, and obfuscation analysis
- **ML Classification** — scikit-learn classifiers (Random Forest, etc.) on extracted feature vectors
- **Weighted Risk Scoring** — instant 0–100 risk score with Low / Medium / High verdict
- **Interactive Dashboard** — risk gauge, tabbed feature breakdown, and scan history
- **API Integration Slots** — VirusTotal, Google Safe Browsing, WHOIS (configurable)

---

## 🚀 Quick Start

```bash
git clone https://github.com/<your-username>/Malicious-URL-Detector.git
cd Malicious-URL-Detector
python -m venv venv && venv\Scripts\activate   # Windows
pip install -r requirements.txt
streamlit run app.py
```

---

## 📁 Project Structure

```
├── heuristics.py      # 35-feature URL extraction engine
├── ai_model.py        # ML model training & prediction
├── apis.py            # Threat intelligence API integrations
├── app.py             # Streamlit web application
├── requirements.txt   # Dependencies
└── README.md
```

---

## 🔬 Heuristic Features (35 Signals)

| Category | Signals | Examples |
|----------|---------|---------|
| 🔐 Protocol & Domain | 9 | HTTPS check, IP-as-host, suspicious TLD, punycode, non-standard port |
| 🔤 Lexical | 6 | Phishing keywords, brand impersonation, @ symbol, URL shortener |
| 📏 Length & Complexity | 6 | URL / path / query length, token count, avg token length |
| 🏗️ Structural | 10 | Subdomain count, directory depth, dot/slash/hyphen counts, double-slash redirect |
| 🕵️ Obfuscation & Entropy | 7 | Shannon entropy, digit/letter ratio, %-encoding, consecutive char repetition |

---

## 📚 Dataset & References

> **Dataset:** [Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) — 651,191 labeled URLs (Kaggle)
>
> Vanhoenshoven et al. (2020) — *"ML for Malicious URL Detection"* · Sahoo et al. (2017) — *"Malicious URL Detection using ML: A Survey"*

---

## 📄 License

For educational and research purposes.
