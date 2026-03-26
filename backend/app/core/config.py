from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    gemini_api_key: str = ""
    groq_api_key: str = ""
    ai_provider: str = "gemini"
    max_file_size_mb: int = 10
    max_log_lines: int = 10000

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
