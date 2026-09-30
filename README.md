# Blockchain-Backed Cloud Storage Verification

MCA final-year project: Flask, PostgreSQL, S3/MinIO, AES-256-GCM, SHA-256 and Hyperledger Fabric.

## Setup (Windows PowerShell)

    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    copy .env.example .env
    cd backend
    python run.py

Open http://localhost:5000 and http://localhost:5000/api/health

## Tests

    cd backend
    pytest

## Docker

    copy .env.example .env
    docker compose up --build