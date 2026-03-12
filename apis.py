import base64
import os

import requests
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