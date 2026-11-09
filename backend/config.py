from pydantic_settings import BaseSettings

DEFAULT_JWT_SECRET = "alertiq-change-this-in-production"


class Settings(BaseSettings):
    database_url: str = "postgresql://alertiq:alertiq123@localhost:5432/alertiq"
    dedup_window_seconds: int = 300
    slack_webhook_url: str = ""
    jwt_secret: str = DEFAULT_JWT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Open self-registration after the first (admin) user. Off = admin creates accounts.
    allow_registration: bool = False
    # If set, POST /alerts/ingest requires header "X-API-Key: <value>".
    ingest_api_key: str = ""

    # AI triage backend:
    #   auto       -> anthropic if ANTHROPIC_API_KEY is set, else claude_cli if the
    #                 `claude` command is installed, else rules
    #   anthropic  -> Claude API (paid, needs ANTHROPIC_API_KEY)
    #   claude_cli -> Claude Code CLI (`claude -p`), uses your Claude login, no API key
    #   ollama     -> local model via Ollama
    #   rules      -> built-in deterministic rules, free and offline
    ai_provider: str = "auto"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    claude_cli_model: str = "sonnet"
    claude_cli_timeout: int = 120
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:4b"
    ollama_num_ctx: int = 4096

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
