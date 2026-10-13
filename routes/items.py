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

# all routes inside this document will start with 'items'
router = APIRouter(prefix="/items", tags=["Items"])
templates = Jinja2Templates(directory="templates") # templates will be here

# where pictures will be stored, directory will be created if not existing
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# create - publish item page
@router.get("/create", response_class=HTMLResponse)
async def create_item_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    # categories will appear to select
    categories = session.exec(select(Category)).all()
    return templates.TemplateResponse(
        request,
        "create_item.html",
        {"user": current_user, "categories": categories},
    )

# create item post
@router.post("/create")
async def create_item(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    category_id: int = Form(...),
    image: UploadFile = File(...),  # Required image file parameter
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Process new item creation with mandatory image validation."""
    categories = session.exec(select(Category)).all()

    # Validate that an actual image file was provided
    if not image or not image.filename:
        return templates.TemplateResponse(
            request,
            "create_item.html",
            {
                "user": current_user,
                "categories": categories,
                "error": "An image is required to publish an item."
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Save uploaded image file to disk
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


# See LIKED items
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
            select(Item).where(Item.id.in_(liked_item_ids), Item.is_blacklisted == False)
        ).all()

    return templates.TemplateResponse(
        request,
        "liked_items.html",
        {"user": current_user, "items": items},
    )

@router.get("/my-items", response_class=HTMLResponse)
async def my_items_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Display the list of items published or listed by the current logged-in user."""
    items = session.exec(
        select(Item).where(Item.seller_id == current_user.id)
    ).all()

    # Identify which of the seller's items have already been purchased
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

# Item details
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


# like or dislike item
@router.post("/{item_id}/like")
async def toggle_like(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    #looks for row that connects user with item in DB
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


#Buy item
@router.post("/{item_id}/buy")
async def buy_item(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    #registers the sell of a product
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

# --- VIEW MY PUBLISHED ITEMS ---

