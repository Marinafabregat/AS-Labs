from uuid import UUID

from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from sqlmodel import Session

from db import engine
from user_reports import is_user_reported


def user_report_context(request: Request) -> dict[str, bool]:
    user_id = request.session.get("user_id")
    if not user_id:
        return {"current_user_is_reported": False}

    try:
        parsed_user_id = UUID(user_id)
    except (TypeError, ValueError):
        return {"current_user_is_reported": False}

    with Session(engine) as session:
        return {
            "current_user_is_reported": is_user_reported(session, parsed_user_id)
        }


templates = Jinja2Templates(
    directory="templates",
    context_processors=[user_report_context],
)
