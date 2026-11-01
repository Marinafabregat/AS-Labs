import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Cargar las variables de entorno antes de importar módulos
# que dependan de ellas.
load_dotenv()

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from authz import can, item_attrs, init_authzforce
from auth import get_current_user_optional, hash_password
from db import engine, get_session, init_db
from image_storage import save_image, migrate_plaintext_uploads
from models import (
    Category,
    Item,
    ItemReport,
    Like,
    ModPetition,
    Purchase,
    User,
    UserRole,
)
from routes import admin, items, mod, oauth_routes, users
from template_context import templates
from fastapi.responses import Response

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

project_root = Path(__file__).parent
uploads_dir = project_root / "uploads"
uploads_dir.mkdir(parents=True, exist_ok=True)

db_path = (
    Path(engine.url.database)
    if engine.url.database
    else project_root / "database.db"
)

IN_DOCKER = os.path.exists("/app")


def seed_default_data(engine):
    """Crea los datos iniciales del marketplace."""
    with Session(engine) as session:
        if session.exec(select(User)).first():
            log.info("Los datos iniciales ya existen.")
            return

        # Guardar las imágenes iniciales cifradas.
        # save_image debe cifrar los bytes antes de escribirlos en uploads/.
        for seed_img in ("keyboard.jpg", "textbook.jpg"):
            src = project_root / "static" / seed_img
            if src.exists():
                save_image(seed_img, src.read_bytes())

        # Usuarios iniciales.
        admin_user = User(
            username="admin",
            email="admin@marketplace.com",
            hashed_password=hash_password("admin123"),
            role=UserRole.ADMIN,
        )

        mod_user = User(
            username="moderator",
            email="mod@marketplace.com",
            hashed_password=hash_password("mod123"),
            role=UserRole.MODERATOR,
        )

        seller_user = User(
            username="alice_seller",
            email="alice@example.com",
            hashed_password=hash_password("user123"),
            role=UserRole.USER,
        )

        buyer_user = User(
            username="bob_buyer",
            email="bob@example.com",
            hashed_password=hash_password("user123"),
            role=UserRole.USER,
        )

        session.add_all([
            admin_user,
            mod_user,
            seller_user,
            buyer_user,
        ])
        session.commit()

        for user in (
            admin_user,
            mod_user,
            seller_user,
            buyer_user,
        ):
            session.refresh(user)

        # Categorías iniciales.
        cat_electronics = Category(name="Electronics")
        cat_books = Category(name="Books")

        session.add_all([cat_electronics, cat_books])
        session.commit()

        session.refresh(cat_electronics)
        session.refresh(cat_books)

    
        item1 = Item(
            title="Vintage Mechanical Keyboard",
            description=(
                "Fully working retro mechanical keyboard "
                "with tactile blue switches."
            ),
            price=75.00,
            image_filename="keyboard.jpg",
            seller_id=seller_user.id,
            category_id=cat_electronics.id,
        )

        item2 = Item(
            title="Introduction to Computer Networks",
            description="Hardcover textbook in great condition.",
            price=25.50,
            image_filename="textbook.jpg",
            seller_id=seller_user.id,
            category_id=cat_books.id,
        )

        session.add_all([item1, item2])
        session.commit()

        session.refresh(item1)
        session.refresh(item2)

        # Interacciones de prueba.
        session.add_all([
            Like(
                user_id=buyer_user.id,
                item_id=item1.id,
            ),
            Purchase(
                buyer_id=buyer_user.id,
                item_id=item2.id,
                price_paid=25.50,
            ),
            ItemReport(
                item_id=item1.id,
                reporter_id=mod_user.id,
                reason="Item title contains questionable keywords.",
            ),
            ModPetition(
                user_id=seller_user.id,
                message=(
                    "I'd like to apply to be a community moderator."
                ),
            ),
        ])

        session.commit()
        log.info("Datos iniciales del marketplace creados correctamente.")


@asynccontextmanager
async def lifespan(app: FastAPI):

    # XACML.
    init_authzforce()

    n = migrate_plaintext_uploads()

    if n:
        log.info("Se han cifrado %s imágenes antiguas.", n)
    else:
        log.info("No hay imágenes antiguas que necesiten cifrado.")

    if db_path.exists():
        log.info(
            "La base de datos ya existe; se conservarán los datos actuales."
        )
        init_db()
    else:
        log.info("No existe la base de datos; se creará con datos iniciales.")
        init_db()
        seed_default_data(engine)

    yield


app = FastAPI(
    title="OnlineMarketplace-Application Security Assignment",
    description=(
        "Application Security assignment implementing security "
        "design principles in an online marketplace."
    ),
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


SESSION_SECRET = os.getenv("SESSION_SECRET_KEY")

if not SESSION_SECRET:
    if IN_DOCKER:
        raise RuntimeError(
            "SESSION_SECRET_KEY es obligatoria en Docker/producción."
        )

    SESSION_SECRET = secrets.token_urlsafe(32)
    log.warning(
        "SESSION_SECRET_KEY no definida: "
        "se utiliza una clave temporal de desarrollo."
    )


env_https_only = os.getenv("SESSION_HTTPS_ONLY")

if env_https_only is None:
    env_https_only = "true" if IN_DOCKER else "false"


app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=env_https_only.lower() == "true",
    same_site="lax",
    max_age=60 * 60 * 8,
)


app.mount("/static", StaticFiles(directory="static"), name="static")


app.include_router(users.router)
app.include_router(oauth_routes.router)
app.include_router(items.router)
app.include_router(mod.router)
app.include_router(admin.router)


log.info("Marketplace application VINSEC started successfully.")


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(get_current_user_optional),
):
    categories = session.exec(select(Category)).all()
    all_items = session.exec(select(Item)).all()

    visible_items = [
        item
        for item in all_items
        if can(user, "read", "item", item_attrs(item))
    ]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "categories": categories,
            "items": visible_items,
            "user": user,
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
):
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "status_code": exc.status_code,
            "detail": exc.detail,
        },
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "status_code": 400,
            "detail": "Datos de formulario no válidos",
        },
        status_code=400,
    )


@app.exception_handler(Exception)
async def general_exception_handler(
    request: Request,
    exc: Exception,
):
    log.exception("Error no controlado")

    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "status_code": 500,
            "detail": "Error interno del servidor",
        },
        status_code=500,
    )

#THIS IS TO ENSURE SECURITY HEADERS ARE PROPERLY INCLUDED
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    
    response.headers["X-Frame-Options"] = "DENY"
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "img-src 'self' data: https:;"
    )
    response.headers["X-Application"] = "vinsec"
    return response
