from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    is_admin: Optional[bool] = False

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    
    class Config:
        from_attributes = True

class IssueCreate(BaseModel):
    title: str
    description: str
    latitude: float
    longitude: float
    address: Optional[str] = None
    category: str

class IssueUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to_id: Optional[int] = None

class IssueResponse(BaseModel):
    id: int
    title: str
    description: str
    ai_generated_report: Optional[str]
    latitude: float
    longitude: float
    address: Optional[str]
    category: str
    image_path: Optional[str]
    status: str
    priority: str
    reporter_id: int
    assigned_to_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True