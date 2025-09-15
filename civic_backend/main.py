from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import uvicorn
import os
import shutil

from database import SessionLocal, engine, Base
from models import User, Issue
from schemas import UserCreate, UserResponse, IssueCreate, IssueResponse, IssueUpdate
from auth import get_password_hash, verify_password, create_access_token, verify_token
from ai_processor import process_image_and_generate_report

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Civic Issue Reporting System",
    description="A crowdsourced platform for reporting and resolving civic issues",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get current user
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    user_id = verify_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

@app.get("/")
async def root():
    return {"message": "Civic Issue Reporting System API"}

@app.get("/index.html")
async def get_frontend():
    return FileResponse("index.html")

@app.get("/api_overview.html") 
async def get_overview():
    return FileResponse("api_overview.html")

@app.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        is_admin=user_data.is_admin or False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return UserResponse(
        id=db_user.id,
        username=db_user.username,
        email=db_user.email,
        is_admin=db_user.is_admin
    )

@app.post("/auth/login")
async def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer", "user": UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        is_admin=user.is_admin
    )}

@app.post("/issues/", response_model=IssueResponse)
async def create_issue(
    title: str = Form(...),
    description: str = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    address: Optional[str] = Form(None),
    category: str = Form(...),
    image: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Process image and generate AI report
    ai_report = await process_image_and_generate_report(image, category)
    
    # Save image
    os.makedirs("uploads", exist_ok=True)
    image_path = f"uploads/{image.filename}"
    with open(image_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)
    
    # Create issue
    db_issue = Issue(
        title=title,
        description=description,
        ai_generated_report=ai_report,
        latitude=latitude,
        longitude=longitude,
        address=address,
        category=category,
        image_path=image_path,
        status="TODO",
        priority="P2",  # Default priority
        reporter_id=current_user.id
    )
    
    db.add(db_issue)
    db.commit()
    db.refresh(db_issue)
    
    return IssueResponse(
        id=db_issue.id,
        title=db_issue.title,
        description=db_issue.description,
        ai_generated_report=db_issue.ai_generated_report,
        latitude=db_issue.latitude,
        longitude=db_issue.longitude,
        address=db_issue.address,
        category=db_issue.category,
        image_path=db_issue.image_path,
        status=db_issue.status,
        priority=db_issue.priority,
        reporter_id=db_issue.reporter_id,
        assigned_to_id=db_issue.assigned_to_id,
        created_at=db_issue.created_at,
        updated_at=db_issue.updated_at
    )

@app.get("/issues/", response_model=List[IssueResponse])
async def get_issues(
    category: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    radius_km: Optional[float] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Issue)
    
    if category:
        query = query.filter(Issue.category == category)
    if status:
        query = query.filter(Issue.status == status)
    if priority:
        query = query.filter(Issue.priority == priority)
    
    # Basic location filtering (for production, use PostGIS or similar)
    if latitude and longitude and radius_km:
        # Simple bounding box filter
        lat_delta = radius_km / 111  # Rough conversion
        lng_delta = radius_km / (111 * abs(latitude))
        
        query = query.filter(
            Issue.latitude.between(latitude - lat_delta, latitude + lat_delta),
            Issue.longitude.between(longitude - lng_delta, longitude + lng_delta)
        )
    
    issues = query.order_by(Issue.created_at.desc()).all()
    
    return [IssueResponse(
        id=issue.id,
        title=issue.title,
        description=issue.description,
        ai_generated_report=issue.ai_generated_report,
        latitude=issue.latitude,
        longitude=issue.longitude,
        address=issue.address,
        category=issue.category,
        image_path=issue.image_path,
        status=issue.status,
        priority=issue.priority,
        reporter_id=issue.reporter_id,
        assigned_to_id=issue.assigned_to_id,
        created_at=issue.created_at,
        updated_at=issue.updated_at
    ) for issue in issues]

@app.put("/issues/{issue_id}", response_model=IssueResponse)
async def update_issue(
    issue_id: int,
    issue_update: IssueUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    # Only admin or reporter can update
    if not current_user.is_admin and issue.reporter_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this issue")
    
    # Update fields
    for field, value in issue_update.dict(exclude_unset=True).items():
        setattr(issue, field, value)
    
    db.commit()
    db.refresh(issue)
    
    return IssueResponse(
        id=issue.id,
        title=issue.title,
        description=issue.description,
        ai_generated_report=issue.ai_generated_report,
        latitude=issue.latitude,
        longitude=issue.longitude,
        address=issue.address,
        category=issue.category,
        image_path=issue.image_path,
        status=issue.status,
        priority=issue.priority,
        reporter_id=issue.reporter_id,
        assigned_to_id=issue.assigned_to_id,
        created_at=issue.created_at,
        updated_at=issue.updated_at
    )

@app.post("/admin/assign/{issue_id}")
async def assign_issue(
    issue_id: int,
    assigned_username: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    assigned_user = db.query(User).filter(User.username == assigned_username).first()
    if not assigned_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    issue.assigned_to_id = assigned_user.id
    db.commit()
    
    return {"message": f"Issue assigned to {assigned_username}"}

@app.get("/categories/")
async def get_categories():
    return {
        "categories": [
            "Road Damage",
            "Garbage/Litter",
            "Broken Streetlight",
            "Graffiti",
            "Damaged Signage",
            "Blocked Drainage",
            "Illegal Parking",
            "Other"
        ]
    }

@app.get("/priorities/")
async def get_priorities():
    return {
        "priorities": ["P0", "P1", "P2", "P3", "P4"],
        "descriptions": {
            "P0": "Critical - Safety hazard",
            "P1": "High - Major infrastructure issue",
            "P2": "Medium - Standard civic issue",
            "P3": "Low - Minor inconvenience",
            "P4": "Lowest - Cosmetic issue"
        }
    }

@app.get("/statuses/")
async def get_statuses():
    return {
        "statuses": ["TODO", "Under Construction", "Solved"]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)