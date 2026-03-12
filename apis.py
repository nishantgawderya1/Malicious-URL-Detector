from dotenv import load_dotenv
import os

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")