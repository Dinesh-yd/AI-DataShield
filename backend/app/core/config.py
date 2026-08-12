from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI DataShield"
    api_prefix: str = "/api/v1"
    database_url: str = "sqlite:///./aidatashield.db"
    # Legacy external provider settings (intentionally unused in mock mode)
    hibp_api_key: str = ""
    hibp_base_url: str = "https://haveibeenpwned.com/api/v3"
    mock_breach_mode: bool = True
    mock_breach_db_path: str = "app/data/mock_breach_db.json"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    breach_monitor_enabled: bool = False
    breach_monitor_interval_seconds: int = 300
    smtp_sender: str = "noreply@aidatashield.local"
    smtp_enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_username: str = ""
    smtp_password: str = ""
    allowed_origins: str = "*"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
