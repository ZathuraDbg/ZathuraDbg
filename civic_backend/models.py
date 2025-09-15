from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    reported_issues = relationship("Issue", foreign_keys="[Issue.reporter_id]", back_populates="reporter")
    assigned_issues = relationship("Issue", foreign_keys="[Issue.assigned_to_id]", back_populates="assigned_to")

class Issue(Base):
    __tablename__ = "issues"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    ai_generated_report = Column(Text)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    address = Column(String(500))
    category = Column(String(50), nullable=False)
    image_path = Column(String(500))
    status = Column(String(20), default="TODO")  # TODO, Under Construction, Solved
    priority = Column(String(5), default="P2")  # P0, P1, P2, P3, P4
    reporter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    reporter = relationship("User", foreign_keys=[reporter_id], back_populates="reported_issues")
    assigned_to = relationship("User", foreign_keys=[assigned_to_id], back_populates="assigned_issues")