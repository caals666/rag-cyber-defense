"""FastAPI entry point.  Run locally:  uvicorn main:app --reload"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config
from api.routes import router
from graph.connection import driver


@asynccontextmanager
async def lifespan(app):
    yield
    driver.close()


app = FastAPI(title="RAG for Robust Cyber Defense", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS,
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(router)
