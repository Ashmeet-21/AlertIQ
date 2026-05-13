from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://alertiq:alertiq123@localhost:5432/alertiq"
    dedup_window_seconds: int = 300
    slack_webhook_url: str = ""
    jwt_secret: str = "alertiq-change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    anthropic_api_key: str = ""

    model_config = {"env_file": ".env"}


settings = Settings()
