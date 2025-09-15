# Civic Issue Reporting and Resolution System

A FastAPI-based crowdsourced platform for reporting and resolving civic issues in communities.

## Features

### User Features
- 📱 **Image Upload**: Take and upload photos of civic issues
- 📍 **Location Selection**: GPS-based location tagging
- 🤖 **AI Report Generation**: Automatic analysis and report generation from uploaded images
- ✏️ **Editable Reports**: Users can modify AI-generated reports before submission
- 🏷️ **Issue Categorization**: Multiple predefined categories (Road Damage, Garbage, Streetlights, etc.)

### Admin Features
- 🗂️ **Issue Management**: Sort issues by category, location, status, and priority
- 🏷️ **Status Tracking**: TODO/Under Construction/Solved workflow
- ⚡ **Priority System**: P0-P4 priority levels
- 👥 **User Assignment**: Assign issues to specific users by username
- 📊 **Filtering & Sorting**: Advanced filtering by multiple criteria

### Technical Features
- 🔐 **JWT Authentication**: Secure user authentication
- 💾 **SQLite Database**: Lightweight database for development
- 🎨 **Responsive UI**: Modern web interface
- 🌍 **Location Services**: Geolocation integration
- 📡 **RESTful API**: Well-documented API endpoints

## Quick Start

### Prerequisites
- Python 3.8+
- pip3

### Installation & Setup

1. **Navigate to the backend directory:**
   ```bash
   cd civic_backend
   ```

2. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Start the server:**
   ```bash
   ./start.sh
   ```
   
   Or manually:
   ```bash
   python3 main.py
   ```

4. **Access the application:**
   - **Frontend**: http://localhost:8000/index.html
   - **API Documentation**: http://localhost:8000/docs
   - **API Base URL**: http://localhost:8000

## API Endpoints

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login

### Issues
- `POST /issues/` - Create new issue (with image upload)
- `GET /issues/` - Get issues (with filtering)
- `PUT /issues/{issue_id}` - Update issue

### Admin
- `POST /admin/assign/{issue_id}` - Assign issue to user

### Metadata
- `GET /categories/` - Get available categories
- `GET /priorities/` - Get priority levels
- `GET /statuses/` - Get status options

## Data Models

### User
- ID, Username, Email, Password (hashed)
- Admin flag
- Relationships to reported and assigned issues

### Issue
- Title, Description, AI-generated report
- Location (latitude, longitude, address)
- Category, Status, Priority
- Image path
- Reporter and assigned user references
- Timestamps

## Issue Categories

- Road Damage
- Garbage/Litter  
- Broken Streetlight
- Graffiti
- Damaged Signage
- Blocked Drainage
- Illegal Parking
- Other

## Priority Levels

- **P0**: Critical - Safety hazard
- **P1**: High - Major infrastructure issue  
- **P2**: Medium - Standard civic issue
- **P3**: Low - Minor inconvenience
- **P4**: Lowest - Cosmetic issue

## Status Workflow

1. **TODO**: Newly reported issue
2. **Under Construction**: Issue being actively worked on
3. **Solved**: Issue has been resolved

## AI Integration

The system includes a mock AI processor that generates reports based on:
- Issue category
- Uploaded image analysis (mock implementation)

For production deployment, replace the mock processor with actual AI services like:
- OpenAI Vision API
- Google Cloud Vision API
- AWS Rekognition

## Development

### Project Structure
```
civic_backend/
├── main.py              # FastAPI application
├── models.py            # SQLAlchemy models
├── schemas.py           # Pydantic schemas
├── database.py          # Database configuration
├── auth.py              # Authentication utilities
├── ai_processor.py      # AI image processing (mock)
├── requirements.txt     # Python dependencies
├── start.sh             # Startup script
├── index.html           # Frontend interface
└── uploads/             # Image storage directory
```

### Database Schema
The SQLite database includes two main tables:
- `users` - User authentication and profile data
- `issues` - Civic issue reports with full metadata

### Security Considerations
- Passwords are hashed using bcrypt
- JWT tokens for API authentication
- Input validation using Pydantic
- File upload restrictions (images only)

## Production Deployment

For production deployment, consider:

1. **Database**: Replace SQLite with PostgreSQL/MySQL
2. **File Storage**: Use cloud storage (AWS S3, Google Cloud Storage)
3. **AI Services**: Integrate real AI vision APIs
4. **Security**: Update JWT secret keys, enable HTTPS
5. **Caching**: Add Redis for session management
6. **Monitoring**: Add logging and monitoring
7. **Scaling**: Use Docker and container orchestration

## Contributing

This is a demonstration implementation of a civic issue reporting system. The core features are functional and ready for further development and customization.

## License

This project is built as a technical demonstration and includes all the requested features from the problem statement.