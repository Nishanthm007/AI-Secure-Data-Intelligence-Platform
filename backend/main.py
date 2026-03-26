from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.api.ws_routes import ws_router

app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    description="AI Gateway + Scanner + Log Analyzer + Risk Engine",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
app.include_router(ws_router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "name": "AI Secure Data Intelligence Platform",
        "version": "1.0.0",
        "docs": "/docs",
    }
