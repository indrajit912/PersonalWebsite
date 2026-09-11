import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, Text, ForeignKey, Date, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

def generate_short_uuid():
    """Generates a stable, short 16-character hex string from UUID."""
    return uuid.uuid4().hex[:16]

class Collaboration(Base):
    """
    Explicit association model for collaboration relationships between two collaborators.
    """
    __tablename__ = 'collaborations'

    collaborator1_id = Column(String(16), ForeignKey('collaborators.id', ondelete='CASCADE'), primary_key=True)
    collaborator2_id = Column(String(16), ForeignKey('collaborators.id', ondelete='CASCADE'), primary_key=True)
    
    status = Column(String(20), default='established') # 'established', 'ongoing'
    created_at = Column(DateTime, default=datetime.utcnow)

    collaborator1 = relationship('Collaborator', foreign_keys=[collaborator1_id], back_populates='source_collaborations')
    collaborator2 = relationship('Collaborator', foreign_keys=[collaborator2_id], back_populates='target_collaborations')

class WorkAuthor(Base):
    """
    Association model connecting Works to Collaborators, preserving author order.
    """
    __tablename__ = 'work_authors'

    work_id = Column(String(16), ForeignKey('works.id', ondelete='CASCADE'), primary_key=True)
    collaborator_id = Column(String(16), ForeignKey('collaborators.id', ondelete='CASCADE'), primary_key=True)
    
    author_order = Column(Integer, nullable=False, default=1)
    is_corresponding = Column(Boolean, default=False)

    work = relationship('Work', back_populates='authors')
    collaborator = relationship('Collaborator', back_populates='work_authors')

class Collaborator(Base):
    __tablename__ = 'collaborators'

    id = Column(String(16), primary_key=True, default=generate_short_uuid)
    is_self = Column(Boolean, default=False, nullable=False, index=True)
    
    # Core Information
    full_name = Column(String(150), nullable=False, index=True)
    nickname = Column(String(150), unique=True, nullable=True, index=True)
    email = Column(String(120), nullable=True)
    
    # Affiliation Details
    affiliation = Column(String(200), nullable=True)
    department = Column(String(150), nullable=True)
    position = Column(String(100), nullable=True)
    institution = Column(String(150), nullable=True)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    
    # Online Profiles
    website = Column(String(255), nullable=True)
    orcid = Column(String(50), nullable=True, unique=True)
    google_scholar_url = Column(String(255), nullable=True)
    linkedin_url = Column(String(255), nullable=True)
    
    bio = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    source_collaborations = relationship('Collaboration', foreign_keys=[Collaboration.collaborator1_id], back_populates='collaborator1', cascade="all, delete-orphan")
    target_collaborations = relationship('Collaboration', foreign_keys=[Collaboration.collaborator2_id], back_populates='collaborator2', cascade="all, delete-orphan")
    work_authors = relationship('WorkAuthor', back_populates='collaborator', cascade="all, delete-orphan")

    def get_collaborators(self):
        targets = [(c.collaborator2, c.status) for c in self.source_collaborations]
        sources = [(c.collaborator1, c.status) for c in self.target_collaborations]
        return targets + sources

    def add_collaboration(self, session, other_collaborator, status='established'):
        if self.id == other_collaborator.id: return
        id1, id2 = sorted([self.id, other_collaborator.id])
        existing = session.query(Collaboration).filter_by(collaborator1_id=id1, collaborator2_id=id2).first()
        if existing:
            existing.status = status
        else:
            collab = Collaboration(collaborator1_id=id1, collaborator2_id=id2, status=status)
            session.add(collab)

class Work(Base):
    __tablename__ = 'works'

    id = Column(String(16), primary_key=True, default=generate_short_uuid)
    title = Column(String(500), nullable=False)
    subtitle = Column(String(500), nullable=True)
    abstract = Column(Text, nullable=True)
    work_type = Column(String(50), default='journal_paper', index=True)
    status = Column(String(50), default='published', index=True)
    display_order = Column(Integer, default=0, index=True) # Used to control display sequence on UI
    
    publication_date = Column(String(50), nullable=True) # e.g. 'Nov 2024'
    year = Column(Integer, nullable=True, index=True)
    publisher = Column(String(200), nullable=True)
    journal_conference = Column(String(300), nullable=True)
    volume = Column(String(50), nullable=True)
    issue = Column(String(50), nullable=True)
    pages = Column(String(50), nullable=True)
    
    doi = Column(String(100), nullable=True, unique=True, index=True)
    arxiv_id = Column(String(50), nullable=True, unique=True, index=True)
    researchgate_url = Column(String(255), nullable=True)
    url = Column(String(255), nullable=True)
    pdf_url = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    authors = relationship('WorkAuthor', back_populates='work', cascade="all, delete-orphan", order_by='WorkAuthor.author_order')
