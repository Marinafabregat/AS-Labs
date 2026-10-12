import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import JSONResponse,RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlmodel import Session, select 
from contextlib import asynccontextmanager

from models import Base, User

from db import engine, init_db, get_session
from models import Category, Item, ItemReport, Like, ModPetition, Purchase, User, UserRole
from auth import hash_password, verify_password, get_current_user, get_current_user_optional
from routes import users, auth
from datetime import datetime


load_dotenv() #secure site we'll probably have some keys in the environment or similar

project_root = os.path.dirname(os.path.dirname(__file__))
db_path = os.path.join(project_root, "database.db")
uploads_dir = os.path.join(project_root, "uploads") 
os.makedirs(uploads_dir, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # IF YOU WANT DEFAULT DATA
    if os.path.isfile(db_path):
        print("database.db already exists, delete file if you'd like to start with default values")
        init_db()
    else:
        print("database.db not found creating one with default values")
        init_db()
        seed_default_data(engine)
    yield

app = FastAPI(
    title="OnlineMarketplace-Application Security Assingment",
    description=(
        "This application is the assignment for Application Security, where several security design principles are applied in a practical environment"
    ),
    lifespan=lifespan
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "dev-secret-change-in-production"),
    https_only=False,
    same_site="lax",
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

app.include_router(users.router)
app.include_router(auth.router)
#app.include_router(items.router)
#app.include_router(mod.router)
#app.include_router(admin.router)

print("Marketplace application VINSEC started successfully.")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, session: Session = Depends(get_session),user=Depends(get_current_user_optional)):
    # Fetch categories and active items for the home page
    categories = session.exec(select(Category)).all()
    items = session.exec(select(Item)).all()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"categories": categories, "items": items, "user": user},
    )



@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={"status_code": exc.status_code, "detail": exc.detail},
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={"status_code": 400, "detail": str(exc.errors())},
        status_code=400,
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={"status_code": 500, "detail": str(exc)},
        status_code=500,
    )

def seed_default_data(engine):
    """Populate the database with default marketplace data for testing."""
    with Session(engine) as session:
        # Check if data already exists to avoid duplicate entries
        existing_users = session.exec(select(User)).first()
        if existing_users:
            print("Default data already seeded.")
            return

        # 1. Users & Roles
        admin_user = User(
            username="admin",
            email="admin@marketplace.com",
            hashed_password=hash_password("admin123"),
            role=UserRole.ADMIN
        )

        mod_user = User(
            username="moderator",
            email="mod@marketplace.com",
            hashed_password=hash_password("mod123"),
            role=UserRole.MODERATOR
        )

        seller_user = User(
            username="alice_seller",
            email="alice@example.com",
            hashed_password=hash_password("user123"),
            role=UserRole.USER
        )

        buyer_user = User(
            username="bob_buyer",
            email="bob@example.com",
            hashed_password=hash_password("user123"),
            role=UserRole.USER
        )

        session.add_all([admin_user, mod_user, seller_user, buyer_user])
        session.commit()
        # Refresh to obtain generated primary key UUIDs
        session.refresh(admin_user)
        session.refresh(mod_user)
        session.refresh(seller_user)
        session.refresh(buyer_user)

        # 2. Categories
        cat_electronics = Category(name="Electronics")
        cat_books = Category(name="Books")

        session.add_all([cat_electronics, cat_books])
        session.commit()
        session.refresh(cat_electronics)
        session.refresh(cat_books)

        # 3. Items
        item1 = Item(
            title="Vintage Mechanical Keyboard",
            description="Fully working retro mechanical keyboard with tactile blue switches.",
            price=75.00,
            image_filename="keyboard.jpg",
            seller_id=seller_user.id,
            category_id=cat_electronics.id
        )

        item2 = Item(
            title="Introduction to Computer Networks",
            description="Hardcover textbook in great condition.",
            price=25.50,
            image_filename="textbook.jpg",
            seller_id=seller_user.id,
            category_id=cat_books.id
        )

        session.add_all([item1, item2])
        session.commit()
        session.refresh(item1)
        session.refresh(item2)

        # 4. Interactions (Like, Purchase, Report, Petition)
        item_like = Like(
            user_id=buyer_user.id,
            item_id=item1.id
        )

        item_purchase = Purchase(
            buyer_id=buyer_user.id,
            item_id=item2.id,
            price_paid=25.50
        )

        mod_report = ItemReport(
            item_id=item1.id,
            reporter_id=mod_user.id,
            reason="Item title contains questionable keywords. Requesting admin review."
        )

        mod_petition = ModPetition(
            user_id=seller_user.id,
            message="I'd like to apply to be a community moderator."
        )

        session.add_all([item_like, item_purchase, mod_report, mod_petition])
        session.commit()

        print("Default marketplace data seeded successfully.")