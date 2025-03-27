import jwt
import datetime
import os
from flask import request, jsonify
from dotenv import load_dotenv
import sqlite3
import uuid
from functools import wraps
from flask import request, jsonify

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
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1),  # Token expires in 15 days
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
            return None, {"status": "Token expired, please log in again"}, 498
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
        
    def jwt_required(self, required_role=None):
        """Decorator to secure API endpoints and enforce RBAC"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                decoded_token, error_response, status_code = self.verify_token()
                if error_response:
                    return jsonify(error_response), status_code
                
                # Role based access control
                if required_role == "superuser" and not self.is_superuser(decoded_token.get("admin_id")):
                    return jsonify({"status": "Unauthorized access! Superusers only."}), 403
                
                if required_role == "org_admin" and decoded_token.get ("isadmin") != "true":
                    return jsonify({"status": "Unauthorized access! Organization admins only."}), 403
                
                # If no specific role is required, proceed with the request
                return func(decoded_token, *args, **kwargs)
            
            return wrapper
        return decorator

auth = Auth()               