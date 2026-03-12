# Malicious URL Detector

A Streamlit-based URL security analyzer that combines handcrafted URL heuristics, a trained machine-learning model, and threat-intelligence lookups.

## Current Features (Implemented)

- 35-feature heuristic extraction engine in `heuristics.py`.
- Binary ML detection pipeline in `ai_model.py`.
- RandomForest model training on the `malicious_phish.csv` dataset.
- Model persistence via `joblib` (`model.pkl`) and runtime prediction in the app.
- Weighted risk scoring (0-100) with `Low Risk`, `Medium Risk`, and `High Risk` verdicts.
- Plotly risk gauge visualization for scan results.
- Detailed feature breakdown tabs in the UI:
	- Protocol and domain
	- Lexical
	- Length
	- Structure
	- Obfuscation
- VirusTotal integration in `apis.py`:
	- URL lookup by encoded URL ID
	- Auto-submit when URL is not yet known to VirusTotal
	- Safe error handling and status messages
- Scan history stored in Streamlit session state.
- Clear history action from the dashboard.

## Integrations Status

- VirusTotal: Implemented.
- Google Safe Browsing: Placeholder UI only (pending backend integration).
- WHOIS lookup: Placeholder UI only (pending backend integration).

## Model and Data

- Dataset file: `malicious_phish.csv`.
- Label mapping used in training:
	- `benign -> 0`
	- `phishing -> 1`
	- `defacement -> 1`
	- `malware -> 1`
- Train/test split: 80/20 (`random_state=42`).
- Default classifier: `RandomForestClassifier(n_estimators=100, random_state=42)`.

## Quick Start

```bash
git clone https://github.com/<your-username>/Malicious-URL-Detector.git
cd Malicious-URL-Detector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python ai_model.py      # generates model.pkl
streamlit run app.py
```

## Environment Variables

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

If `VIRUSTOTAL_API_KEY` is missing, the app continues to work and returns a clear VirusTotal error message in the UI.

## Project Structure

```text
ai_model.py          # Model training and export (model.pkl)
apis.py              # VirusTotal API integration
app.py               # Streamlit frontend and prediction workflow
heuristics.py        # 35 URL heuristic features
malicious_phish.csv  # Training dataset
requirements.txt     # Python dependencies
README.md
```

## References

- Kaggle: Malicious URLs Dataset (sid321axn).
- Vanhoenshoven et al. (2020), Machine Learning for Malicious URL Detection.
- Sahoo et al. (2017), Malicious URL Detection using Machine Learning: A Survey.

## License

For educational and research purposes.
