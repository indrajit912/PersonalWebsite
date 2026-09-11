import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

DB_FILE = os.path.join(os.path.dirname(__file__), 'research_network.db')
engine = create_engine(f'sqlite:///{DB_FILE}', echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    print(f"Database initialized at {DB_FILE}")

def get_session():
    return SessionLocal()
