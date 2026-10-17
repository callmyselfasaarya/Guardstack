import os
from pathlib import Path
from pydantic import BaseModel
from dotenv import load_dotenv

# Load .env if present
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR.parent / ".env")
load_dotenv(BASE_DIR / ".env")

class Settings(BaseModel):
    PROJECT_NAME: str = "Guardstack"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./guardstack.db")
    
    # Security & Tokens
    SECRET_KEY: str = os.getenv("SECRET_KEY", "guardstack-secret-key-change-in-production-32bytes")
    
    # GitHub App Integration
    GITHUB_APP_ID: str = os.getenv("GITHUB_APP_ID", "")
    GITHUB_PRIVATE_KEY_PATH: str = os.getenv("GITHUB_PRIVATE_KEY_PATH", "")
    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    
    # AI Engine Provider: 'heuristic' (mock offline), 'gemini', 'openai', 'anthropic', 'ollama'
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "heuristic")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
    
    # Threat Feeds
    EPSS_API_URL: str = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
    CISA_KEV_URL: str = os.getenv("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    FEED_CACHE_HOURS: int = 24
    
    # DAST Verification
    DAST_CHALLENGE_FILE: str = "/.well-known/guardstack-challenge.txt"
    DAST_ALLOW_LOCALHOST: bool = True
    
    # Workdir for temporary repos and patch checks
    WORKSPACE_TMP_DIR: Path = BASE_DIR / "workspace_tmp"

settings = Settings()
settings.WORKSPACE_TMP_DIR.mkdir(parents=True, exist_ok=True)
