import base64
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_virustotal(url):
	if not VT_API_KEY:
		return {"error": "VirusTotal API key not found."}

	url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
	lookup_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
	headers = {"x-apikey": VT_API_KEY}

	try:
		response = requests.get(lookup_endpoint, headers=headers, timeout=15)
		if response.status_code == 404:
			submit_response = requests.post(
				"https://www.virustotal.com/api/v3/urls",
				headers=headers,
				data={"url": url},
				timeout=15,
			)
			submit_response.raise_for_status()
			return {
				"queued": True,
				"message": "URL submitted to VirusTotal for analysis. Try scanning again in a moment.",
			}

		response.raise_for_status()
		data = response.json()
		stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
		return {
			"queued": False,
			"malicious": stats.get("malicious", 0),
			"suspicious": stats.get("suspicious", 0),
			"harmless": stats.get("harmless", 0),
			"undetected": stats.get("undetected", 0),
		}
	except requests.RequestException as exc:
		return {"error": f"VirusTotal request failed: {exc}"}


def url_age_calculate(url, suspicious_days=180):
	"""Calculate domain age from WHOIS data and flag very new domains as suspicious."""
	parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
	domain = parsed.netloc.split(":")[0].strip().lower()

	if not domain:
		return {"error": "Could not parse a valid domain from the URL."}

	try:
		whois_data = whois.whois(domain)
		creation_date = whois_data.creation_date

		# Many WHOIS providers return multiple creation dates; use the earliest one.
		if isinstance(creation_date, list):
			creation_date = min(d for d in creation_date if d is not None) if creation_date else None

		if creation_date is None:
			return {"error": "WHOIS did not return a creation date for this domain."}

		if isinstance(creation_date, str):
			creation_date = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))

		if creation_date.tzinfo is None:
			creation_date = creation_date.replace(tzinfo=timezone.utc)

		now = datetime.now(timezone.utc)
		age_days = (now - creation_date).days
		age_days = max(age_days, 0)
		age_years = round(age_days / 365, 2)
		is_suspicious = age_days < suspicious_days

		if is_suspicious:
			message = (
				f"Domain age is {age_days} days (~{age_years} years). "
				f"This is below {suspicious_days} days and may be suspicious."
			)
		else:
			message = f"Domain age is {age_days} days (~{age_years} years)."

		return {
			"domain": domain,
			"age_days": age_days,
			"age_years": age_years,
			"is_suspicious": is_suspicious,
			"message": message,
		}
	except Exception as exc:
		return {"error": f"WHOIS lookup failed: {exc}"}