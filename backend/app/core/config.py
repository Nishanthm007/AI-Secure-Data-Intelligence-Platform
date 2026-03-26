from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    openai_api_key: str = ""
    ai_provider: str = "openai"
    max_file_size_mb: int = 10
    max_log_lines: int = 10000
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
