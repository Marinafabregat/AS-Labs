import io
import math
import uuid
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from PIL import Image, UnidentifiedImageError
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from auth import get_current_active_user, get_current_user_optional, get_or_create_csrf_token, verify_csrf
from authz import (
    can,
    enforce,
    item_attrs,
    report_create_attrs,
    role_of,
    user_pii_attrs,
)
from db import get_session
from image_storage import (
    delete_image,
    is_valid_name,
    load_image,
    media_type,
    save_image,
)
from models import (
    Category,
    Item,
    ItemReport,
    Like,
    Purchase,
    ReportStatus,
    User,
)
from security_encryption import decrypt_pii
from template_context import templates

router = APIRouter(prefix="/items", tags=["Items"])

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_REPORT_REASON_LENGTH = 500

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}
VALID_EXTENSIONS_BY_FORMAT = {
    "JPEG": {".jpg", ".jpeg"},
    "PNG": {".png"},
    "WEBP": {".webp"},
}
FORMAT_EXTENSIONS = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}

# Example images copied at seed time. They are never deleted.
SEED_IMAGES = {"keyboard.jpg", "textbook.jpg"}

# IMAGE HELPERS

async def read_upload_limited(image: UploadFile) -> bytes:
    """Read an upload in chunks and stop as soon as it exceeds the size limit."""
    chunks = []
    total_size = 0

    while True:
        chunk = await image.read(64 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_FILE_SIZE:
            raise ValueError("File size exceeds the 5MB limit.")
        chunks.append(chunk)

    return b"".join(chunks)


def validate_image(contents: bytes, filename: str) -> tuple[Image.Image, str]:
    """
    Check the real content of an upload, not only its name.
    Returns the decoded image and its real format (JPEG, PNG or WEBP).
    Raises ValueError with a user-facing message if the image is not valid.
    """
    file_ext = Path(filename).suffix.lower()

    if file_ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Invalid file extension. Only JPG, PNG, and WEBP images are allowed."
        )
    if not contents:
        raise ValueError("The uploaded image is empty.")
    if len(contents) > MAX_FILE_SIZE:
        raise ValueError("File size exceeds the 5MB limit.")

    try:
        # verify() checks the structure but leaves the object unusable,
        # so the image is opened a second time to decode it.
        with Image.open(io.BytesIO(contents)) as probe:
            probe.verify()

        with Image.open(io.BytesIO(contents)) as img:
            real_format = (img.format or "").upper()
            if real_format not in ALLOWED_FORMATS:
                raise ValueError("The uploaded file is not a valid or supported image.")
            if file_ext not in VALID_EXTENSIONS_BY_FORMAT[real_format]:
                raise ValueError("The image extension does not match its actual format.")
            img.load()
            decoded = img.copy()

    except ValueError:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise ValueError("The uploaded file is not a valid or supported image.") from exc
    except Exception as exc:
        raise ValueError("The uploaded file is not a valid or supported image.") from exc

    return decoded, real_format


def encode_and_store_image(img: Image.Image, fmt: str) -> str:
    """
    Re-encode the validated image, encrypt it and store it.
    The name is a server-generated UUID, so the client filename is never used.
    Re-encoding drops EXIF metadata and any data appended to the file.
    """
    name = f"{uuid.uuid4().hex}{FORMAT_EXTENSIONS[fmt]}"
    buffer = io.BytesIO()
    img.save(buffer, format=fmt)
    save_image(name, buffer.getvalue())
    return name


def discard_image(name: Optional[str]) -> None:
    """Delete a stored image. Seed images are never deleted."""
    if not name or name in SEED_IMAGES:
        return
    delete_image(name)


def error_message(exc: Exception) -> str:
    """User-facing message from a ValueError or an HTTPException."""
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    return str(exc)


def render_item_form_error(request, template_name, context, message):
    """Re-render an item form with a validation error."""
    context["error"] = message
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=context,
        status_code=status.HTTP_400_BAD_REQUEST,
    )


def validate_item_fields(title, description, price, category_id, session) -> None:
    """Validate the business fields of an item."""
    if not title.strip():
        raise HTTPException(status_code=400, detail="The item title cannot be empty.")
    if not description.strip():
        raise HTTPException(status_code=400, detail="The item description cannot be empty.")
    if not math.isfinite(price) or price <= 0:
        raise HTTPException(status_code=400, detail="The price must be a positive, finite number.")
    if session.get(Category, category_id) is None:
        raise HTTPException(status_code=400, detail="The selected category does not exist.")


def require_private_items_access(current_user: User) -> None:
    """XACML decides whether the user may see their own private item lists."""
    enforce(current_user, "read", "user_pii", user_pii_attrs(current_user))


def load_item_or_404(session: Session, item_id: int) -> Item:
    """Load an item or raise 404. Authorization is checked by the caller."""
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

# IMAGES (decrypted in memory, authorized by XACML)

@router.get("/{item_id}/image")
async def item_image(
    item_id: int,
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Serve an item image only if XACML lets the viewer read the item."""
    item = load_item_or_404(session, item_id)

    if not item.image_filename or not is_valid_name(item.image_filename):
        raise HTTPException(status_code=404, detail="Image not found")

    # Hidden items return 404, so the image cannot be fetched by guessing the URL.
    if not can(current_user, "read", "item", item_attrs(item)):
        raise HTTPException(status_code=404, detail="Image not found")

    try:
        data = load_image(item.image_filename)
    except (FileNotFoundError, InvalidTag, ValueError):
        raise HTTPException(status_code=404, detail="Image not found")

    return Response(
        content=data,
        media_type=media_type(item.image_filename),
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "inline",
        },
    )

# CREATE

@router.get("/create", response_class=HTMLResponse)
async def create_item_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    enforce(current_user, "create", "item", {})
    categories = session.exec(select(Category)).all()
    return templates.TemplateResponse(
        request=request,
        name="create_item.html",
        context={"user": current_user, "categories": categories, "csrf_token": get_or_create_csrf_token(request)},
        
    )

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
    csrf_token: str = Form(...),
):
    # Authorization happens before any file is read or stored.
    enforce(current_user, "create", "item", {})
    verify_csrf(request, csrf_token)
    categories = session.exec(select(Category)).all()
    form_context = {"user": current_user, "categories": categories}

    if not image or not image.filename:
        return render_item_form_error(
            request, "create_item.html", form_context,
            "An image is required to publish an item.",
        )

    try:
        validate_item_fields(title, description, price, category_id, session)
        contents = await read_upload_limited(image)
        img, fmt = validate_image(contents, image.filename)
    except (HTTPException, ValueError) as exc:
        return render_item_form_error(
            request, "create_item.html", form_context, error_message(exc),
        )
    finally:
        await image.close()

    image_name = encode_and_store_image(img, fmt)

    new_item = Item(
        title=title.strip(),
        description=description.strip(),
        price=price,
        category_id=category_id,
        seller_id=current_user.id,
        image_filename=image_name,
    )

    try:
        session.add(new_item)
        session.commit()
        session.refresh(new_item)
    except Exception:
        session.rollback()
        discard_image(image_name)
        raise

    return RedirectResponse(
        url=f"/items/{new_item.id}", status_code=status.HTTP_302_FOUND
    )

# LISTS

@router.get("/liked", response_class=HTMLResponse)
async def liked_items_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    require_private_items_access(current_user)

    likes = session.exec(select(Like).where(Like.user_id == current_user.id)).all()
    liked_item_ids = [like.item_id for like in likes]

    items = []
    if liked_item_ids:
        candidates = session.exec(select(Item).where(Item.id.in_(liked_item_ids))).all()
        items = [i for i in candidates if can(current_user, "read", "item", item_attrs(i))]

    return templates.TemplateResponse(
        request=request,
        name="liked_items.html",
        context={"user": current_user, "items": items},
    )


@router.get("/purchased", response_class=HTMLResponse)
async def get_purchased_items(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    require_private_items_access(current_user)

    purchased_ids = session.exec(
        select(Purchase.item_id).where(Purchase.buyer_id == current_user.id)
    ).all()

    items = []
    if purchased_ids:
        candidates = session.exec(select(Item).where(Item.id.in_(purchased_ids))).all()
        items = [i for i in candidates if can(current_user, "read", "item", item_attrs(i))]

    return templates.TemplateResponse(
        request=request,
        name="purchased.html",
        context={"user": current_user, "items": items},
    )


@router.get("/my-items", response_class=HTMLResponse)
async def my_items_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    require_private_items_access(current_user)

    candidates = session.exec(
        select(Item).where(Item.seller_id == current_user.id)
    ).all()

    # Hidden items leave the seller's list because the read policy hides them
    # from non-staff. This is intentional.
    items = [i for i in candidates if can(current_user, "read", "item", item_attrs(i))]

    item_ids = [i.id for i in items if i.id is not None]
    sold_item_ids = set()
    if item_ids:
        sold_item_ids = set(
            session.exec(
                select(Purchase.item_id).where(Purchase.item_id.in_(item_ids))
            ).all()
        )

    return templates.TemplateResponse(
        request=request,
        name="my_items.html",
        context={
            "user": current_user,
            "items": items,
            "sold_item_ids": sold_item_ids,
        },
    )

# EDIT

@router.get("/{item_id}/edit", response_class=HTMLResponse)
async def edit_item_page(
    request: Request,
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = load_item_or_404(session, item_id)
    enforce(current_user, "update", "item", item_attrs(item))

    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400, detail="Cannot edit a product that has already been sold"
        )

    categories = session.exec(select(Category)).all()
    return templates.TemplateResponse(
        request=request,
        name="edit_item.html",
        context={"user": current_user, "item": item, "categories": categories, "csrf_token": get_or_create_csrf_token(request)},
        
    )


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
    csrf_token: str = Form(...),
):
    item = load_item_or_404(session, item_id)
    enforce(current_user, "update", "item", item_attrs(item))
    verify_csrf(request, csrf_token)
    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400, detail="Cannot edit a product that has already been sold"
        )

    categories = session.exec(select(Category)).all()
    form_context = {"user": current_user, "item": item, "categories": categories}

    try:
        validate_item_fields(title, description, price, category_id, session)
    except HTTPException as exc:
        return render_item_form_error(
            request, "edit_item.html", form_context, error_message(exc),
        )

    new_image_name = None
    if image and image.filename:
        try:
            contents = await read_upload_limited(image)
            img, fmt = validate_image(contents, image.filename)
            # Store the new image before the commit. The old one is removed
            # only after the commit succeeds.
            new_image_name = encode_and_store_image(img, fmt)
        except (HTTPException, ValueError) as exc:
            return render_item_form_error(
                request, "edit_item.html", form_context, error_message(exc),
            )
        finally:
            await image.close()

    old_image_name = item.image_filename

    item.title = title.strip()
    item.description = description.strip()
    item.price = price
    item.category_id = category_id
    if new_image_name:
        item.image_filename = new_image_name

    try:
        session.add(item)
        session.commit()
        session.refresh(item)
    except Exception:
        session.rollback()
        discard_image(new_image_name)
        raise

    if new_image_name and old_image_name != new_image_name:
        discard_image(old_image_name)

    return RedirectResponse(
        url=f"/items/{item.id}", status_code=status.HTTP_302_FOUND
    )

# DELETE

@router.post("/{item_id}/delete")
async def delete_item(
    request: Request,
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
    csrf_token: str = Form(...),
):
    item = load_item_or_404(session, item_id)
    enforce(current_user, "delete", "item", item_attrs(item))
    verify_csrf(request, csrf_token)
    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400, detail="Cannot delete a product that has already been sold"
        )

    likes = session.exec(select(Like).where(Like.item_id == item_id)).all()
    image_to_delete = item.image_filename

    try:
        for like in likes:
            session.delete(like)
        session.delete(item)
        session.commit()
    except Exception:
        session.rollback()
        raise

    # The file is removed only after the database row is gone.
    discard_image(image_to_delete)

    return RedirectResponse(
        url="/items/my-items", status_code=status.HTTP_302_FOUND
    )

# REPORT

@router.post("/{item_id}/report")
async def report_item(
    request: Request,
    item_id: int,
    reason: str = Form(...),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
    csrf_token: str = Form(...),
):
    item = load_item_or_404(session, item_id)
    verify_csrf(request, csrf_token)
    seller = session.get(User, item.seller_id)
    if seller is None:
        raise HTTPException(status_code=404, detail="Seller not found")

    # Authorize before validating the reason, so the response does not
    # reveal anything about the item's state.
    report_attrs = report_create_attrs(item.seller_id, role_of(seller))
    enforce(current_user, "create", "report", report_attrs)

    clean_reason = reason.strip()
    if len(clean_reason) > MAX_REPORT_REASON_LENGTH:
        raise HTTPException(
            status_code=400, detail="The report reason cannot exceed 500 characters."
        )

    # XACML decides whether this report goes straight to admins (and hides the
    # item) or stays pending for a moderator.
    if can(current_user, "delete", "item", item_attrs(item)) and can(
        current_user, "report_remove", "item", item_attrs(item)
    ):
        image_to_delete = item.image_filename
        session.delete(item)
        session.commit()
        discard_image(image_to_delete)
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    escalated = can(current_user, "create_escalated", "report", report_attrs)

    new_report = ItemReport(
        item_id=item.id,
        reporter_id=current_user.id,
        reason=clean_reason or "No reason provided",
        status=ReportStatus.FOR_ADMIN if escalated else ReportStatus.PENDING,
    )
    session.add(new_report)

    if escalated:
        item.is_blacklisted = True
        session.add(item)

    session.commit()

    return RedirectResponse(
        url=f"/items/{item_id}?reported=true", status_code=status.HTTP_302_FOUND
    )

# ITEM DETAIL

@router.get("/{item_id}", response_class=HTMLResponse)
async def item_detail(
    request: Request,
    item_id: int,
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    item = load_item_or_404(session, item_id)
    resource = item_attrs(item)

    # Hidden items return 404 to viewers without permission.
    if not can(current_user, "read", "item", resource):
        raise HTTPException(status_code=404, detail="Item not found")

    seller = session.get(User, item.seller_id)

    # Every button is decided by XACML. The template only shows or hides them,
    # and each POST route enforces the same decision again.
    ui = {
        "can_edit": can(current_user, "update", "item", resource),
        "can_delete": can(current_user, "delete", "item", resource),
        "can_like": can(current_user, "like", "item", resource),
        "can_buy": can(current_user, "buy", "item", resource),
        "can_report": seller is not None and can(
            current_user,
            "create",
            "report",
            report_create_attrs(item.seller_id, role_of(seller)),
        ),
    }

    is_liked = False
    is_owner = False
    if current_user:
        is_owner = item.seller_id == current_user.id
        is_liked = session.exec(
            select(Like).where(
                Like.user_id == current_user.id, Like.item_id == item.id
            )
        ).first() is not None

    is_purchased = session.exec(
        select(Purchase).where(Purchase.item_id == item.id)
    ).first() is not None

    return templates.TemplateResponse(
        request=request,
        name="item_detail.html",
        context={
            "user": current_user,
            "item": item,
            "seller": seller,
            "ui": ui,
            "is_owner": is_owner,
            "is_liked": is_liked,
            "is_purchased": is_purchased,
            "missing_address_error": request.query_params.get("missing_address") == "true",
            "reported_success": request.query_params.get("reported") == "true",
            "bought_success": request.query_params.get("bought") == "true",
            "csrf_token": get_or_create_csrf_token(request),
        },
    )

# LIKE

@router.post("/{item_id}/like")
async def toggle_like(
    request: Request,
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
    csrf_token: str = Form(...)
):
    item = load_item_or_404(session, item_id)
    enforce(current_user, "like", "item", item_attrs(item))
    verify_csrf(request, csrf_token)
    existing_like = session.exec(
        select(Like).where(
            Like.user_id == current_user.id, Like.item_id == item_id
        )
    ).first()

    if existing_like:
        session.delete(existing_like)
    else:
        session.add(Like(user_id=current_user.id, item_id=item_id))

    session.commit()
    return RedirectResponse(
        url=f"/items/{item_id}", status_code=status.HTTP_302_FOUND
    )

# BUY

@router.post("/{item_id}/buy")
async def buy_item(
    request: Request,
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
    csrf_token: str = Form(...),
):
    item = load_item_or_404(session, item_id)
    verify_csrf(request, csrf_token)
    # XACML covers hidden items and the seller buying their own item.
    enforce(current_user, "buy", "item", item_attrs(item))

    already_bought = session.exec(
        select(Purchase).where(Purchase.item_id == item_id)
    ).first()
    if already_bought:
        raise HTTPException(
            status_code=400, detail="This product has already been sold"
        )

    # Business rule: a delivery address is required. Stored encrypted.
    delivery_address = decrypt_pii(current_user.delivery_address_line1)
    if not delivery_address or not delivery_address.strip():
        return RedirectResponse(
            url=f"/items/{item_id}?missing_address=true",
            status_code=status.HTTP_302_FOUND,
        )

    try:
        session.add(
            Purchase(
                buyer_id=current_user.id,
                item_id=item.id,
                price_paid=item.price,
            )
        )
        session.commit()
    except IntegrityError:
        # The unique constraint on item_id blocks a concurrent second purchase.
        session.rollback()
        raise HTTPException(
            status_code=409, detail="This product has already been sold"
        )

    return RedirectResponse(
        url=f"/items/{item_id}?bought=true", status_code=status.HTTP_302_FOUND
    )