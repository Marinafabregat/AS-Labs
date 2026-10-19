import io
import re
import uuid
from pathlib import Path
from typing import Optional

from PIL import Image
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from auth import get_current_active_user, get_current_user_optional
from db import get_session
from models import (
    Category,
    Item,
    ItemReport,
    Like,
    Purchase,
    ReportStatus,
    User,
    UserRole,
)
from template_context import templates

# All routes inside this document will start with '/items'
router = APIRouter(prefix="/items", tags=["Items"])

# Directory where pictures will be stored
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Security rules for file uploads
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}
FORMAT_TO_EXT = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}


def sanitize_filename(filename: str) -> str:
    """Conserva el nombre original del archivo limpiándolo de caracteres inseguros

    (Path Traversal) y evita colisiones añadiendo sufijos numéricos.
    """
    path = Path(filename)
    stem = path.stem
    ext = path.suffix.lower()

    # Reemplazar espacios y caracteres no alfanuméricos por guiones bajos
    safe_stem = re.sub(r"[^a-zA-Z0-9_-]", "_", stem)
    if not safe_stem:
        safe_stem = "upload"

    safe_name = f"{safe_stem}{ext}"
    destination_path = UPLOAD_DIR / safe_name

    # Evitar sobrescribir fotos existentes con el mismo nombre
    counter = 1
    while destination_path.exists():
        safe_name = f"{safe_stem}_{counter}{ext}"
        destination_path = UPLOAD_DIR / safe_name
        counter += 1

    return safe_name


# --- 1. RUTAS ESTÁTICAS ---


# Publish item page (GET)
@router.get("/create", response_class=HTMLResponse)
async def create_item_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    categories = session.exec(select(Category)).all()
    return templates.TemplateResponse(
        request,
        "create_item.html",
        {"user": current_user, "categories": categories},
    )


# Process item creation with Secure Upload Validation (POST)
@router.post("/create")
async def create_item(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    category_id: int = Form(...),
    image: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    categories = session.exec(select(Category)).all()

    if not image or not image.filename:
        return templates.TemplateResponse(
            request,
            "create_item.html",
            {
                "user": current_user,
                "categories": categories,
                "error": "An image is required to publish an item.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    file_ext = Path(image.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return templates.TemplateResponse(
            request,
            "create_item.html",
            {
                "user": current_user,
                "categories": categories,
                "error": "Invalid file extension. Only JPG, PNG, and WEBP images are allowed.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    contents = await image.read()
    if len(contents) > MAX_FILE_SIZE:
        return templates.TemplateResponse(
            request,
            "create_item.html",
            {
                "user": current_user,
                "categories": categories,
                "error": "File size exceeds the 5MB limit.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        img = Image.open(io.BytesIO(contents))
        img.verify()

        img = Image.open(io.BytesIO(contents))
        real_format = img.format.upper() if img.format else ""

        if real_format not in ALLOWED_FORMATS:
            raise ValueError("Unsupported format")

    except Exception:
        return templates.TemplateResponse(
            request,
            "create_item.html",
            {
                "user": current_user,
                "categories": categories,
                "error": "The uploaded file is not a valid or supported image.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Sanitizar y conservar el nombre original del archivo
    image_filename = sanitize_filename(image.filename)
    file_path = UPLOAD_DIR / image_filename
    img.save(file_path)

    new_item = Item(
        title=title,
        description=description,
        price=price,
        category_id=category_id,
        seller_id=current_user.id,
        image_filename=image_filename,
    )

    session.add(new_item)
    session.commit()
    session.refresh(new_item)

    return RedirectResponse(
        url=f"/items/{new_item.id}", status_code=status.HTTP_302_FOUND
    )


# See Liked Items
@router.get("/liked", response_class=HTMLResponse)
async def liked_items_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    likes = session.exec(
        select(Like).where(Like.user_id == current_user.id)
    ).all()

    liked_item_ids = [like.item_id for like in likes]
    items = []
    if liked_item_ids:
        items = session.exec(
            select(Item).where(Item.id.in_(liked_item_ids))
        ).all()

    return templates.TemplateResponse(
        request,
        "liked_items.html",
        {"user": current_user, "items": items},
    )


# See Purchased Items
@router.get("/purchased", response_class=HTMLResponse)
async def get_purchased_items(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    purchased_item_ids = session.exec(
        select(Purchase.item_id).where(Purchase.buyer_id == current_user.id)
    ).all()

    items = []
    if purchased_item_ids:
        items = session.exec(
            select(Item).where(Item.id.in_(purchased_item_ids))
        ).all()

    return templates.TemplateResponse(
        request,
        "purchased.html",
        {"user": current_user, "items": items},
    )


# See My Published Items
@router.get("/my-items", response_class=HTMLResponse)
async def my_items_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    items = session.exec(
        select(Item).where(Item.seller_id == current_user.id)
    ).all()

    item_ids = [item.id for item in items if item.id is not None]
    sold_item_ids = set()
    if item_ids:
        purchases = session.exec(
            select(Purchase.item_id).where(Purchase.item_id.in_(item_ids))
        ).all()
        sold_item_ids = set(purchases)

    return templates.TemplateResponse(
        request,
        "my_items.html",
        {
            "user": current_user,
            "items": items,
            "sold_item_ids": sold_item_ids,
        },
    )


# --- 2. RUTAS DINÁMICAS (EDICIÓN, BORRADO, REPORTE Y DETALLES) ---


@router.get("/{item_id}/edit", response_class=HTMLResponse)
async def edit_item_page(
    request: Request,
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if item.seller_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="You are not authorized to edit this item"
        )

    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400,
            detail="Cannot edit a product that has already been sold",
        )

    categories = session.exec(select(Category)).all()
    return templates.TemplateResponse(
        request,
        "edit_item.html",
        {"user": current_user, "item": item, "categories": categories},
    )


# Procesar edición de artículo (POST)
@router.post("/{item_id}/edit")
async def edit_item(
    request: Request,
    item_id: int,
    title: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    category_id: int = Form(...),
    image: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if item.seller_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="You are not authorized to edit this item"
        )

    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400,
            detail="Cannot edit a product that has already been sold",
        )

    categories = session.exec(select(Category)).all()

    if image and image.filename:
        file_ext = Path(image.filename).suffix.lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            return templates.TemplateResponse(
                request,
                "edit_item.html",
                {
                    "user": current_user,
                    "item": item,
                    "categories": categories,
                    "error": "Invalid file extension. Only JPG, PNG, and WEBP images are allowed.",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        contents = await image.read()
        if len(contents) > MAX_FILE_SIZE:
            return templates.TemplateResponse(
                request,
                "edit_item.html",
                {
                    "user": current_user,
                    "item": item,
                    "categories": categories,
                    "error": "File size exceeds the 5MB limit.",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            img = Image.open(io.BytesIO(contents))
            img.verify()

            img = Image.open(io.BytesIO(contents))
            real_format = img.format.upper() if img.format else ""

            if real_format not in ALLOWED_FORMATS:
                raise ValueError("Unsupported format")

        except Exception:
            return templates.TemplateResponse(
                request,
                "edit_item.html",
                {
                    "user": current_user,
                    "item": item,
                    "categories": categories,
                    "error": "The uploaded file is not a valid or supported image.",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Borrar foto anterior solo si no pertenece a los datos semilla iniciales
        if item.image_filename and item.image_filename not in [
            "keyboard.jpg",
            "textbook.jpg",
        ]:
            old_file_path = UPLOAD_DIR / item.image_filename
            if old_file_path.exists() and old_file_path.is_file():
                old_file_path.unlink()

        new_filename = sanitize_filename(image.filename)
        new_file_path = UPLOAD_DIR / new_filename
        img.save(new_file_path)
        item.image_filename = new_filename

    item.title = title
    item.description = description
    item.price = price
    item.category_id = category_id

    session.add(item)
    session.commit()
    session.refresh(item)

    return RedirectResponse(
        url=f"/items/{item.id}", status_code=status.HTTP_302_FOUND
    )


# Eliminar artículo (POST)
@router.post("/{item_id}/delete")
async def delete_item(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if item.seller_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You are not authorized to delete this item",
        )

    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a product that has already been sold",
        )

    likes = session.exec(select(Like).where(Like.item_id == item_id)).all()
    for like in likes:
        session.delete(like)

    if item.image_filename and item.image_filename not in [
        "keyboard.jpg",
        "textbook.jpg",
    ]:
        file_path = UPLOAD_DIR / item.image_filename
        if file_path.exists() and file_path.is_file():
            file_path.unlink()

    session.delete(item)
    session.commit()

    return RedirectResponse(
        url="/items/my-items", status_code=status.HTTP_302_FOUND
    )


# Report Item (POST)
@router.post("/{item_id}/report")
async def report_item(
    item_id: int,
    reason: str = Form(...),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if item.seller_id == current_user.id:
        raise HTTPException(
            status_code=400, detail="You cannot report your own listing"
        )

    new_report = ItemReport(
        item_id=item.id,
        reporter_id=current_user.id,
        reason=reason.strip() or "No reason provided",
        status=(
            ReportStatus.FOR_ADMIN
            if current_user.role == UserRole.MODERATOR
            else ReportStatus.PENDING
        ),
    )
    session.add(new_report)

    if new_report.status == ReportStatus.FOR_ADMIN:
        item.is_blacklisted = True
        session.add(item)
    session.commit()

    return RedirectResponse(
        url=f"/items/{item_id}?reported=true",
        status_code=status.HTTP_302_FOUND,
    )


# Item Details (GET)
@router.get("/{item_id}", response_class=HTMLResponse)
async def item_detail(
    request: Request,
    item_id: int,
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    is_liked = False
    is_owner = False
    is_purchased = False

    if current_user:
        if item.seller_id == current_user.id:
            is_owner = True

        existing_like = session.exec(
            select(Like).where(
                Like.user_id == current_user.id, Like.item_id == item.id
            )
        ).first()
        is_liked = existing_like is not None

        existing_purchase = session.exec(
            select(Purchase).where(Purchase.item_id == item.id)
        ).first()
        is_purchased = existing_purchase is not None

    missing_address_error = (
        request.query_params.get("missing_address") == "true"
    )
    reported_success = request.query_params.get("reported") == "true"

    return templates.TemplateResponse(
        request,
        "item_detail.html",
        {
            "user": current_user,
            "item": item,
            "seller": session.get(User, item.seller_id),
            "is_liked": is_liked,
            "is_owner": is_owner,
            "is_purchased": is_purchased,
            "missing_address_error": missing_address_error,
            "reported_success": reported_success,
        },
    )


# Like or Dislike Item (POST)
@router.post("/{item_id}/like")
async def toggle_like(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item or item.is_blacklisted:
        raise HTTPException(
            status_code=400, detail="Item is not available for interaction"
        )

    existing_like = session.exec(
        select(Like).where(
            Like.user_id == current_user.id, Like.item_id == item_id
        )
    ).first()

    if existing_like:
        session.delete(existing_like)
    else:
        new_like = Like(user_id=current_user.id, item_id=item_id)
        session.add(new_like)

    session.commit()
    return RedirectResponse(
        url=f"/items/{item_id}", status_code=status.HTTP_302_FOUND
    )


# Buy Item (POST)
@router.post("/{item_id}/buy")
async def buy_item(
    request: Request,
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item or item.is_blacklisted:
        raise HTTPException(status_code=404, detail="Item not available")

    if item.seller_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot buy own product")

    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400, detail="This product has already been sold"
        )

    user_address = getattr(current_user, "address", None) or getattr(
        current_user, "shipping_address", None
    )
    if not user_address or not str(user_address).strip():
        return RedirectResponse(
            url=f"/items/{item_id}?missing_address=true",
            status_code=status.HTTP_302_FOUND,
        )

    purchase = Purchase(
        buyer_id=current_user.id, item_id=item.id, price_paid=item.price
    )
    session.add(purchase)
    session.commit()

    return RedirectResponse(
        url=f"/items/{item_id}?bought=true", status_code=status.HTTP_302_FOUND
    )