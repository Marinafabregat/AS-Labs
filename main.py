import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import jwt
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker 

from models import Base, User

#There are a lot of imports, but these are probably things we are going to do. 

load_dotenv() #secure site we'll probably have some keys in the environment or similar


app = FastAPI(
    title="OnlineMarketplace-Application Security Assingment",
    description=(
        "This application is the assignment for Application Security, where several security design principles are applied in a practical environment"
    ),
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")



#HERE FOLLOWS THE ENTIRE WEBSITE LOGIC + API

@app.get("/")
def base_endpoint(request:Request):
    """base endpoint""" #these comments are very useful to automatically generate fast api documentation with
    #user = try_get_current_user(request) 
    #if user:
    #    return RedirectResponse(url="/dashboard", status_code=303)
    #return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )