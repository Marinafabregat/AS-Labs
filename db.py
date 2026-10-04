from sqlmodel import SQLModel, create_engine, Session, select
from models import User, Category, Item, Purchase, Like, ItemReport, ModPetition
import os
# Define our SQLite
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
connect_args = {"check_same_thread": False}


# Create the Engine
engine = create_engine(sqlite_url, echo=False, connect_args=connect_args)

def init_db():
    """
    Helper Method to create the initial Database
    and any associated tables.

    This should be called by the application on startup
    """
    SQLModel.metadata.create_all(engine)
    

def get_session():
    """Generator for the Session object, used as dependency in requests
    """
    with Session(engine) as session:
        yield session