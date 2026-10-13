import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from auth import get_current_active_user, get_current_user_optional
from db import get_session
from models import Category, Item, Like, Purchase, User

# All routes inside this document will start with '/items'
router = APIRouter(prefix="/items", tags=["Items"])
templates = Jinja2Templates(directory="templates")

# Directory where pictures will be stored
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


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


# Process item creation (POST)
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

    file_ext = Path(image.filename).suffix
    image_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = UPLOAD_DIR / image_filename

    with open(file_path, "wb") as buffer:
        buffer.write(await image.read())

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
            select(Item).where(
                Item.id.in_(liked_item_ids), Item.is_blacklisted == False
            )
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
    # Usamos buyer_id para buscar las compras del usuario actual
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


# Item Details
@router.get("/{item_id}", response_class=HTMLResponse)
async def item_detail(
    request: Request,
    item_id: int,
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    item = session.get(Item, item_id)
    if not item or item.is_blacklisted:
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

    return templates.TemplateResponse(
        request,
        "item_detail.html",
        {
            "user": current_user,
            "item": item,
            "is_liked": is_liked,
            "is_owner": is_owner,
            "is_purchased": is_purchased,
        },
    )


# Like or Dislike Item
@router.post("/{item_id}/like")
async def toggle_like(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

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


# Buy Item
@router.post("/{item_id}/buy")
async def buy_item(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item or item.is_blacklisted:
        raise HTTPException(status_code=404, detail="Item not available")

    if item.seller_id == current_user.id:
        raise HTTPException(
            status_code=400, detail="Cannot buy own product"
        )

    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400, detail="This product has already been sold"
        )

    purchase = Purchase(
        buyer_id=current_user.id, item_id=item.id, price_paid=item.price
    )
    session.add(purchase)
    session.commit()

    return RedirectResponse(
        url=f"/items/{item_id}?bought=true", status_code=status.HTTP_302_FOUND
    )