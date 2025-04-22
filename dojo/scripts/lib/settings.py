BASE_DOMAIN = "http://localhost:8080/"
BASE_URL = f"{BASE_DOMAIN}api/v2/"
API_KEY = "YOUR_API_KEY_HERE"
HEADERS = {"Authorization": f"Token {API_KEY}", "Content-Type": "application/json"}
HEADERS_FOR_IMPORT = {"Authorization": f"Token {API_KEY}"}

SMTP_SERVER = "YOUR_SMTP_SERVER_HERE"
SMTP_PORT = "YOUR_SMTP_PORT_HERE"  # must be a integer
SMTP_USER = "YOUR_SMTP_USER_HERE"
SMTP_PASS = "YOUR_SMTP_PASS_HERE"
SENDER = f"CHANGE_FOR_THE_USER_TO_APPEAR <{SMTP_USER}>"
USERS_FILE = "user_credentials.txt"
