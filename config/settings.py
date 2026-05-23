import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    ES_CLOUD_ID: str = os.getenv("ES_CLOUD_ID", "")
    ES_API_KEY: str = os.getenv("ES_API_KEY", "")
    ES_API_KEY_ID: str = os.getenv("ES_API_KEY_ID", "")
    ES_USERNAME: str = os.getenv("ES_USERNAME", "elastic")
    ES_PASSWORD: str = os.getenv("ES_PASSWORD", "")
    ES_HOST: str = os.getenv("ES_HOST", "https://localhost:9200")
    ES_INDEX_PREFIX: str = os.getenv("ES_INDEX_PREFIX", "falcohive")

    FALCO_GRPC_HOST: str = os.getenv("FALCO_GRPC_HOST", "localhost")
    FALCO_GRPC_PORT: int = int(os.getenv("FALCO_GRPC_PORT", "5060"))
    DOCKER_SOCKET: str = os.getenv("DOCKER_SOCKET", "/var/run/docker.sock")

    DASHBOARD_HOST: str = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "8080"))

    AGENT_LOG_DIR: str = os.getenv("AGENT_LOG_DIR", str(Path(__file__).parent.parent / "data" / "agent_logs"))
    CONFIDENCE_THRESHOLD: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.6"))
    AUTO_BLOCK_ENABLED: bool = os.getenv("AUTO_BLOCK_ENABLED", "true").lower() == "true"

settings = Settings()
