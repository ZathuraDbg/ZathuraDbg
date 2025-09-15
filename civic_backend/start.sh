#!/bin/bash

# Civic Issue Reporting System Startup Script

echo "🏛️ Starting Civic Issue Reporting System..."

# Change to backend directory
cd "$(dirname "$0")"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Create uploads directory if it doesn't exist
mkdir -p uploads

# Start the FastAPI server
echo "🚀 Starting FastAPI server on http://localhost:8000"
echo "📊 API Documentation available at http://localhost:8000/docs"
echo "🌐 Frontend available at http://localhost:8000/index.html"
echo ""
echo "Press Ctrl+C to stop the server"

python3 main.py