import jwt
import datetime
import os
from flask import request, jsonify
from dotenv import load_dotenv
import sqlite3
import uuid

load_dotenv()


class Auth:
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY")
        self.db_path = os.getenv("DATABASE_PATH")


    def generate_token(self, user_id, isadmin, admin_id=None):
        
        payload = {
            "user_id": user_id,
            "isadmin": isadmin, # "true" or "false"
            "admin_id": admin_id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=15),  # Token expires in 15 days
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def verify_token(self):
        """Extracts and verifies the JWT token from the request header"""
        
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None, {"status": "Unauthorized access! Missing token"}, 401

        try:
            token = auth_header.split(" ")[1]  # Extract token from "Bearer <token>"
            decoded = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return decoded, None, 200
        except jwt.ExpiredSignatureError:
            return None, {"status": "Token expired, please log in again"}, 401
        except jwt.InvalidTokenError:
            return None, {"status": "Invalid token, please log in again"}, 401
        

    def is_superuser(self, admin_id):
        """Check if the provided admin_id belongs to a superuser"""
        if not admin_id:
            return False
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM superusers WHERE admin_id=?", (admin_id,))
                return cursor.fetchone() [0] > 0
        except Exception as e:
            print(f"Superuser check error: {str(e)}")
            return False
        
    def is_org_admin(self, user_id):
        """Check if the provided user_id is an organization admin"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT isadmin FROM users WHERE user_id = ?", (user_id,))
                result = cursor.fetchone()
                return result and result[0] == "true"
        except Exception as e:
            print("Org admin check error:", e)
            return False

auth = Auth()               