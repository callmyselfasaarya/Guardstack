# Application configuration with hardcoded credentials
DEBUG = True
DATABASE_URI = "sqlite:///./app.db"

# True Positive 5: Hardcoded High-Entropy AWS Access Key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# True Positive 6: Hardcoded GitHub Personal Access Token
GITHUB_SYNC_TOKEN = "ghp_9A8b7C6d5E4f3G2h1I0jKlMnOpQrStUvWxYz"
