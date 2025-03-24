import sqlite3
import random
import json
from datetime import datetime, timedelta
import hashlib

class Database:
    def __init__(self):
        self.db_path = '../datastore.db'
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
                              (user_id TEXT, name TEXT, email TEXT, phone TEXT,user_type TEXT,code TEXT,lawfirm_name TEXT,status TEXT,next_date TEXT, password TEXT, isadmin TEXT, date_joined TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS models
                              (model_id TEXT,user_id TEXT,name TEXT,table_name TEXT,model TEXT,n INTEGER)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS chats
                              (chat_id TEXT,user_id TEXT,name TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS messages
                              (chat_id TEXT,user_id TEXT,user TEXT,system TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS media
                              (chat_id TEXT,user_id TEXT,file TEXT,content TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS saved_docs
                              (user_id TEXT, file_id TEXT, filename TEXT, table_id TEXT, table_ TEXT, citation TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS superusers
                              (admin_id TEXT, name TEXT, email TEXT, password TEXT, created_at TEXT)''')

        conn.commit()
        
        # Create default superuser if none exists
        self.create_default_superuser()
        
    def create_default_superuser(self):
        # Create default superuser if none exists
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Check if any superuser exists
                cursor.execute("SELECT COUNT(*) FROM superusers")
                count = cursor.fetchone()[0]
                
                if count == 0:
                    # Create a default superuser
                    admin_id = "admin" + str(random.randint(1000, 9999))
                    name = "Super Admin"
                    email = "admin@super.com"
                    # Default password is "admin123" (hashed)
                    password = self._hash_password("admin123")
                    created_at = str(datetime.now().date())
                    
                    cursor.execute("INSERT INTO superusers (admin_id, name, email, password, created_at) VALUES (?, ?, ?, ?, ?)",
                                   (admin_id, name, email, password, created_at))
                    conn.commit()
                    print(f"Default superuser created with email: {email} and password: {password}")
        except Exception as e:
            print("Error creating default superuser: " + str(e))
            
    def _hash_password(self, password):
        # Hash password using SHA-256
        return hashlib.sha256(password.encode()).hexdigest()
    
    # Add new superuser
    def add_superuser(self, admin_id, name, email, password):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Verify the requesting admin is a valid superuser
                cursor.execute("SELECT * FROM superusers WHERE admin_id=?", (admin_id,))
                requesting_admin = cursor.fetchone()
                if not requesting_admin:
                    return {"status": "Unauthorized access!"}
                
                # Check if the superuser already exists
                cursor.execute("SELECT * FROM superusers WHERE email=?", (email,))
                existing_admin = cursor.fetchone()
                if existing_admin:
                    return {"status": "Superuser with this email already exists"}
                
                # Create a new superuser
                new_admin_id = "admin" + str(random.randint(1000, 9999))
                
                # Hash the password before inserting
                hashed_password = self._hash_password(password)
                created_at = str(datetime.now().date())
                
                cursor.execute("INSERT INTO superusers (admin_id, name, email, password, created_at) VALUES (?,?,?,?,?)",
                                   (new_admin_id, name, email, hashed_password, created_at))
                conn.commit()
                return {"status": "success", admin_id: new_admin_id}
        except Exception as e:
            return {"status": "Error: " + str(e)}
    
    # Superuser login
    def superuser_login(self, email, password):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Hash the password before checking
                hashed_password = self._hash_password(password)
                # Check if the email and password match for super user
                cursor.execute("SELECT * FROM superusers WHERE email=? AND password=?", (email, hashed_password))
                admin = cursor.fetchone()
                if admin:
                    admin_id = admin[0]
                    return {"status": "success","admin":admin_id}
                else:
                    return {"status": "Invalid email or password"}
        except Exception as e:
            return {"status": "Error: " + str(e)}
        
     # Change superuser password
    def change_superuser_password(self, admin_id, old_password, new_password):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Hash the old password before checking
                hashed_old_password = self._hash_password(old_password)
                # Check if the old password matches
                cursor.execute("SELECT * FROM superusers WHERE admin_id=? AND password=?", (admin_id, hashed_old_password))
                admin = cursor.fetchone()
                if not admin:
                    return {"status": "Invalid Password"}
                
                    # Hash the new password before updating
                hashed_new_password = self._hash_password(new_password)
                # Update password
                cursor.execute("UPDATE superusers SET password=? WHERE admin_id=?", (hashed_new_password, admin_id))
                conn.commit()
                return {"status": "success"}

        except Exception as e:
            return {"status": "Error: " + str(e)}  
        
    # Get all superusers
    def get_superusers(self, admin_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Verify the requesting admin is a valid superuser 
                cursor.execute("SELECT * FROM superusers WHERE admin_id=?", (admin_id,))
                requesting_admin = cursor.fetchone()
                if not requesting_admin:
                    return {"status": "Unauthorized access!"}
                
                # Get all superusers
                cursor.execute("SELECT admin_id, name, email, created_at FROM superusers")
                admins = cursor.fetchall()
                
                admins_list = []
                for admin in admins:
                    admin_data = {
                        "admin_id": admin[0],
                        "name": admin[1],
                        "email": admin[2],
                        "created_at": admin[3]
                    }
                    admins_list.append(admin_data)
                
                return {"status": "success", "superusers": admins_list}
        except Exception as e:
            return {"status": "Error: " + str(e)}
        
    # Delete superuser
    def delete_superuser(self, admin_id, admin_to_delete_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Verify the requesting admin is a valid superuser 
                cursor.execute("SELECT * FROM superusers WHERE admin_id=?", (admin_id,))
                requesting_admin = cursor.fetchone()
                if not requesting_admin:
                    return {"status": "Unauthorized access!"}
                
                # Cannot delete self
                if admin_id == admin_to_delete_id:
                    return {"status": "Cannot delete your own account!"}
                
                # Check how many superusers exist
                cursor.execute("SELECT COUNT(*) FROM superusers")
                count = cursor.fetchone()[0]
                if count <= 1:
                    return {"status": "Cannot delete the last superuser!"}
                
                # Check if the superuser to be deleted exists
                cursor.execute("SELECT * FROM superusers WHERE admin_id=?", (admin_to_delete_id,))
                admin_to_delete = cursor.fetchone()
                if not admin_to_delete:
                    return {"status": "Superuser does not exist"}
                
                # Delete the superuser
                cursor.execute("DELETE FROM superusers WHERE admin_id=?", (admin_to_delete_id,))
                conn.commit()
                
                # Get updated list of superusers
                cursor.execute("SELECT admin_id, name, email, created_at FROM superusers")
                admins = cursor.fetchall()
                
                admins_list = []
                for admin in admins:
                    admin_data = {
                        "admin_id": admin[0],
                        "name": admin[1],
                        "email": admin[2],
                        "created_at": admin[3]
                    }
                    admins_list.append(admin_data)
                
                return {"status": "success", "superusers": admins_list}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    def add_user(self, name, email, phone,user_type,code, lawfirm_name, password, isadmin):
        user_id = "user" + str(random.randint(1000, 9999))
        status = "trial"
        if isadmin=="true":
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Generate a random code until a unique one is found
                while True:
                    new_code = random.randint(10000,99999)
                    cursor.execute("SELECT * FROM users WHERE code=?", (new_code,))
                    if not cursor.fetchone():
                        code=new_code
                        break
        current_datetime = datetime.now()
        date_joined = str(current_datetime.date())
        
        # Set billing date to 7 days from now
        next_billing_date = current_datetime + timedelta(days=7)
        next_date=str(next_billing_date.date())
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE email=?", (email,))
                existing_user = cursor.fetchone()
                if existing_user:
                    return {"status": "Email already exists"}
                cursor.execute("INSERT INTO users (user_id, name, email, phone, user_type, code, lawfirm_name, status, next_date, password, isadmin, date_joined) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (user_id, name, email, phone,user_type, code, lawfirm_name, status, next_date, password, isadmin, date_joined))
                conn.commit()
                return {"status": "success","user":user_id}
        except Exception as e:
            return {"status": "Error: " + str(e)}
    
    # Super user delete user
    def delete_user(self, admin_id, user_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Verify requester is a superuser
                cursor.execute("SELECT * FROM superusers WHERE admin_id=?", (admin_id,))
                requesting_admin = cursor.fetchone()

                if not requesting_admin:
                    return {"status": "Unauthorized access! Invalid superuser ID."}
                
                # Verify user exists
                cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
                existing_user = cursor.fetchone()
                print(f"User Found: {existing_user}")
                if not existing_user:
                    return {"status": "User does not exist!"}
                # Delete user
                cursor.execute("DELETE FROM users WHERE user_id=?", (user_id,))
                conn.commit()
                return {"status":"success"}
        except Exception as e:
            return {"status":"Error: " + str(e)}
        
    # Admin register user using code
    def admin_add_user(self, admin_id, name, email, phone, password):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Check if the admin exists and has admin priviledges
                cursor.execute("SELECT * FROM users WHERE user_id=? AND isadmin='true'", (admin_id,))
                admin = cursor.fetchone()
                if not admin:
                    return {"status": "Unauthorized access!"}
                
                # Get admin's code and lawfirm name
                admin_code = admin[5]
                lawfirm_name = admin[6]

                # Check if the email already exists
                cursor.execute("SELECT * FROM users WHERE email=?", (email,))
                existing_user = cursor.fetchone()
                if existing_user:
                    return {"status": "Email already exists"}
                
                # Create a new user
                user_id = "user" + str(random.randint(1000, 9999))
                user_type = "org"
                isadmin = "false" # Regular user
                status = "trial"
                
                current_datetime = datetime.now()
                date_joined = str(current_datetime.date())
                
                # Set billing date same as admin
                next_billing_date = current_datetime + timedelta(days=7)
                next_date=str(next_billing_date.date())
                
                # Insert new user
                cursor.execute("INSERT INTO users (user_id, name, email, phone, user_type, code, lawfirm_name, status, next_date, password, isadmin, date_joined) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (user_id, name, email, phone, user_type, admin_code, lawfirm_name, status, next_date, password, isadmin, date_joined))
                conn.commit()
                return {"status": "success","user":user_id}
        except Exception as e:
            return {"status": "Error: " + str(e)}
 
    # Org Admin delete user in org
    def admin_delete_user(self, admin_id, user_id_to_delete):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Check if the admin exists and has admin priviledges
                cursor.execute("SELECT * FROM users WHERE user_id=? AND isadmin='true'", (admin_id,))
                admin = cursor.fetchone()
                if not admin:
                    return {"status": "Unauthorized access!"}
                
                admin_code = admin[5]
                
                # Check if the user to be deleted exists and belongs to same organization
                cursor.execute("SELECT * FROM users WHERE user_id=? AND code=?", (user_id_to_delete, admin_code))
                user = cursor.fetchone()
                if not user:
                    return {"status": "User does not exist or does not belong to the same organization"}
                
                # Cannot delete admin user
                if admin_id == user_id_to_delete:
                    return {"status": "Cannot delete admin user"}
                
                # Delete the user
                cursor.execute("DELETE FROM users WHERE user_id=?", (user_id_to_delete,))
                conn.commit()
                return {"status": "success"}
        except Exception as e:
            return {"status": "Error: " + str(e)}
        
# Admin get users in orgamization
    def get_org_users(self, admin_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Check if the admin exists and has admin priviledges
                cursor.execute("SELECT * FROM users WHERE user_id=? AND isadmin='true'", (admin_id,))
                admin = cursor.fetchone()
                if not admin:
                    return {"status": "Unauthorized access!", "users":[]}
                
                # Get admin's code
                admin_code = admin[5]
                
                # Get all users in the same organization
                cursor.execute("SELECT * FROM users WHERE code=?", (admin_code,))
                org_users = cursor.fetchall()
                
                # Prepare response
                users_list = []
                for user in org_users:
                    user_data = {
                        "user_id": user[0],
                        "name": user[1],
                        "email": user[2],
                        "phone": user[3],
                        "user_type": user[4],
                        "code": user[5],
                        "lawfirm_name": user[6],
                        "status": user[7],
                        "next_date": user[8],
                        "isadmin": user[10],
                        "date_joined": user[11]
                    }
                    users_list.append(user_data)
                
                return {"status": "success", "users": users_list}
        except Exception as e:
            return {"status": "Error: " + str(e)}
        
    # Admin Update user status
    def update_user_status(self, admin_id, user_id_to_update, new_status):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Check if the admin exists and has admin priviledges
                cursor.execute("SELECT * FROM users WHERE user_id=? AND isadmin='true'", (admin_id,))
                admin = cursor.fetchone()
                if not admin:
                    return {"status": "Unauthorized access!"}
                
                admin_code = admin[5]
                
                # Check if the user to be updated exists and belongs to same organization
                cursor.execute("SELECT * FROM users WHERE user_id=? AND code=?", (user_id_to_update, admin_code))
                user = cursor.fetchone()
                if not user:
                    return {"status": "User does not exist or does not belong to the same organization"}
                
                # Update user status
                cursor.execute("UPDATE users SET status=? WHERE user_id=?", (new_status, user_id_to_update))
                conn.commit()
                return {"status": "success"}
        except Exception as e:
            return {"status": "Error: " + str(e)}
    
    def login(self, email, password):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                #check if email is valid
                cursor.execute("SELECT * FROM users WHERE email=?", (email,))
                email_user = cursor.fetchone()
                if email_user:
                    pass
                else:
                    return {"status": "Account does not exist"}
                # Check if the email and password match
                cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
                user = cursor.fetchone()
                if user:
                    user_id = user[0]
                    next_billing_date = user[8]  # Assuming the next_billing_date is at the 7th index
                    current_date = datetime.now().date()
                    # Check if current date is before the next billing date
                    if current_date < datetime.strptime(next_billing_date, "%Y-%m-%d").date():
                        return {"status": "success", "user": user_id}
                    else:
                        return {"status": "billing required"}
                else:
                    return {"status": "Incorrect password"}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    def admin_login(self, email, password):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Check if the email and password match for admin login
                cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
                user = cursor.fetchone()
                if user:
                    user_id = user[0]
                    return {"status": "success","user":user_id}
                else:
                    return {"status": "Invalid email or password"}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    def change_password(self, user_id, old_password, new_password):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Check if the old password matches
                cursor.execute("SELECT * FROM users WHERE user_id=? AND password=?", (user_id, old_password))
                user = cursor.fetchone()
                if user:
                    # Update password
                    cursor.execute("UPDATE users SET password=? WHERE user_id=?", (new_password, user_id))
                    conn.commit()
                    return {"status": "success"}
                else:
                    return {"status": "Invalid Password"}
        except Exception as e:
            return {"status": "Error: " + str(e)}
        
    def subscribe_user(self, admin_id, user_id, next_date):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Verify the requesting admin is a valid superuser
                cursor.execute("SELECT * FROM superusers WHERE admin_id=?", (admin_id,))
                requesting_admin = cursor.fetchone()
                if not requesting_admin:
                    return {"status": "Unauthorized access!"}
                
                # Verify user exists
                cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
                existing_user = cursor.fetchone()
                if not existing_user:
                    return {"status": "User does not exist!"}
                
                cursor.execute("UPDATE users SET next_date=?, status='Subscribed' WHERE user_id=?", (next_date, user_id))
                conn.commit()
                return {'status':'success'}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    def subscribe_org(self, admin_id, code, next_date):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Verify the requesting admin is a valid superuser
                cursor.execute("SELECT * FROM superusers WHERE admin_id=?", (admin_id,))
                requesting_admin = cursor.fetchone()
                if not requesting_admin:
                    return {"status": "Unauthorized access!"}
                
                cursor.execute("UPDATE users SET next_date=?, status='Subscribed' WHERE code=?", (next_date, code))
                conn.commit()
                return {'status':'success'}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    def user_profile(self, user_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
                user = cursor.fetchone()
                if user:
                    # Base response
                    response = { "status": "success", "name": user[1], "email": user[2], "phone": user[3], "user_type": user[4], "code": user[5], "status": user[7], "next_date": user[8], "isadmin": user[10]}

                    # Add lawfirm name if user type is "org"
                    if user[4] == "org":
                        response["lawfirm_name"] = user[6]
                    
                    return response
                else:
                    return {"status": "User does not exist"}
        except Exception as e:
            print("Error on loading profile: " + str(e))
            return {"status": "Error: " + str(e)}

    def profiles(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users")
                users = cursor.fetchall()
                users_ = []
                for user in users:
                    # Base response  
                    user_data = {"user_id": user[0], "name": user[1], "email": user[2], "phone": user[3], "user_type": user[4], "code": user[5], "status": user[7], "next_date": user[8], "isadmin": user[10], "date_joined": user[11]}
                    
                    # Add lawfirm name if user type is "org"
                    if user[4] == "org":
                        user_data["lawfirm_name"] = user[6]   
                        
                    users_.append(user_data)
                return users_
        except Exception as e:
            print("Error on loading profiles: " + str(e))
            return []


    #-----------------------------------Models, Tables, Messages--------------------



    def add_model(self,user_id,name,table_name,model):
        model_id = "model" + str(random.randint(1000, 9999))
        n=random.randint(100,999)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM models WHERE name=? AND user_id=?", (name,user_id))
                existing_model = cursor.fetchone()
                if existing_model:
                    return {"status": "Model already exists"}
                cursor.execute("INSERT INTO models (model_id,user_id, name,table_name,model,n) VALUES (?, ?, ?, ?, ?,0)",
                               (model_id,user_id, name,table_name,model))
                conn.commit()
            return {"status": "success"}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    def models(self, user_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM models WHERE user_id=? ", (user_id,))
                models_pre = cursor.fetchall()
                models=[]
                for model in models_pre:
                    models.append({"name":model[2],"tool":model[4],"table":model[3],'model_id':model[0]})

                return models
        except Exception as e:
            print("error: "+str(e))
            return []

    def model(self, model_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM models WHERE model_id=? ", (model_id,))
                model = cursor.fetchone()
                if model:
                    return {"name":model[2],"tool":model[4],"table":model[3],'model_id':model[0]}
                else:
                    print("No row")
                    return {}
        except Exception as e:
            print("Error: "+str(e))
            return {}

    def delete_table(self, table_name):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DROP TABLE IF EXISTS " + table_name)
                return {"status":"success"}
        except Exception as e:
            return {"status":"Error: "+str(e)}

    def deli_model(self, model_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM models WHERE model_id=?", (model_id,))
                conn.commit()
                return {"status":"success"}
        except Exception as e:
            return {"status":"Error: "+str(e)}

    #add new chat
    def add_chat(self, user_id,name):
        chat_id = user_id + str(random.randint(1000, 9999))
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO chats (chat_id,user_id, name) VALUES (?, ?, ?)",
                               (chat_id,user_id, name))
                conn.commit()
            return {"status": "success","chat":chat_id}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    #view all chats belonging to a user
    def chats(self, user_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM chats WHERE user_id=? ", (user_id,))
                chats_pre = cursor.fetchall()
                chats=[]
                for chat in chats_pre:
                    chats.append({"chat_id":chat[0],"name":chat[2]})

                return chats
        except Exception as e:
            print("error: "+str(e))
            return []

    #view all chats belonging to a user
    def allchats(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM chats")
                chats_pre = cursor.fetchall()
                chats=[]
                for chat in chats_pre:
                    chats.append({"chat_id":chat[0],"user_id":chat[1],"name":chat[2]})

                return chats
        except Exception as e:
            print("error: "+str(e))
            return []

    #delete a chat, including all its messages
    def deli_chat(self, chat_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM chats WHERE chat_id=?", (chat_id,))
                cursor.execute("DELETE FROM messages WHERE chat_id=?", (chat_id,))
                cursor.execute("DELETE FROM media WHERE chat_id=?", (chat_id,))
                conn.commit()
                return {"status":"success"}
        except Exception as e:
            return {"status":"Error: "+str(e)}

    #add new message
    def add_message(self,chat_id,user_id,user,system):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO messages (chat_id,user_id,user,system) VALUES (?, ?, ?,?)",
                               (chat_id,user_id,user,system))
                conn.commit()
            return {"status": "success","chat":chat_id}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    #view all messages belonging to a chat
    def messages(self, chat_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM messages WHERE chat_id=? ", (chat_id,))
                messages_pre = cursor.fetchall()
                messages=[]
                for message in messages_pre:
                    msg=message[2]
                    msg=msg.replace('\n', '')
                    msg=json.loads(msg)
                    messages.append({"system":msg,"user":message[3]})

                return messages
        except Exception as e:
            print("error: "+str(e))
            return []

    #add new media file
    def add_file(self, chat_id,user_id,file,content):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO media (chat_id,user_id, file,content) VALUES (?, ?, ?, ?)",
                               (chat_id,user_id, file, content))
                conn.commit()
            return {"status": "success","chat":chat_id}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    #view all chats belonging to a user
    def files(self, chat_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM media WHERE chat_id=? ", (chat_id,))
                files_pre = cursor.fetchall()
                files=[]
                for file in files_pre:
                    file.append({"file":file[2],"content":file[3]})

                return files
        except Exception as e:
            print("error: "+str(e))
            return []

    #delete a chat, including all its messages
    def deli_file(self, chat_id, file):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM media WHERE chat_id=? AND file=?", (chat_id,file))
                conn.commit()
                return {"status":"success"}
        except Exception as e:
            return {"status":"Error: "+str(e)}

    #view file
    def file(self, chat_id, file):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM media WHERE chat_id=? AND file=?", (chat_id, file))
                file = cursor.fetchone()
                if file:
                    content = file[3]
                    return {"status": "success","content":content}
                else:
                    return {"status":"none"}
        except Exception as e:
            return {"status": "Error: " + str(e)}





    #--------------------------------------SAVING DOCS----------------------

    # Save a document
    def save_doc(self, user_id, file_id, filename, table_id, table, citation):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("INSERT INTO saved_docs (user_id, file_id, filename, table_id, table_, citation) VALUES (?,?,?,?,?,?)",
                                   (user_id, file_id, filename, table_id, table, citation))
                conn.commit()
                return {"status": "success"}
        except Exception as e:
            return {"status": "Error: " + str(e)}

    #load saved files
    def load_saved(self, user_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM saved_docs WHERE user_id=?", (user_id,))
                docs = cursor.fetchall()
                files=[]
                for doc in docs:
                    files.append({'file_id':doc[1],'filename':doc[2],'table_id':doc[3],'table':doc[4],'citation':doc[5]})

                return {'files':files}
        except Exception as e:
            print(str(e))
            return {"files":[]}

    #delete a saved document
    def deli_saved(self, user_id, file_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM saved_docs WHERE user_id=? AND file_id=?", (user_id,file_id))
                conn.commit()
                return {"status":"success"}
        except Exception as e:
            return {"status":"Error: "+str(e)}


#----------------------USAGE TRACKING------------------------

    def get_user_usage(self, user_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Count chats created by the user
                cursor.execute("SELECT COUNT(*) FROM chats WHERE user_id=?", (user_id,))
                chat_count = cursor.fetchone()[0]
                
                # Count messages sent by the user
                cursor.execute("SELECT COUNT(*) FROM messages WHERE user_id =?", (user_id,))
                message_count = cursor.fetchone()[0]
                
                return {"status": "success", "chat_count": chat_count, "message_count": message_count}
        except Exception as e:
            return {"status": "Error: " + str(e)}
        
    def get_all_users_usage(self, admin_id):
        try:
            if not admin_id:
                return {"status": "Invalid admin_id provided!"}

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if requester is a superuser (Ensure admin_id is a string)
                cursor.execute("SELECT COUNT(*) FROM superusers WHERE admin_id=?", (str(admin_id),))
                if cursor.fetchone()[0] == 0:
                    return {"status": "Unauthorized access!"}

                # Get all users
                cursor.execute("SELECT user_id, name, email FROM users")
                users = cursor.fetchall()

                usage_data = []
                for user in users:
                    user_id, name, email = user

                    # Get chat count
                    cursor.execute("SELECT COUNT(*) FROM chats WHERE user_id=?", (str(user_id),))
                    chat_count = cursor.fetchone()[0]

                    # Get message count
                    cursor.execute("SELECT COUNT(*) FROM messages WHERE user_id=?", (str(user_id),))
                    message_count = cursor.fetchone()[0]

                    usage_data.append({
                        "user_id": user_id,
                        "name": name,
                        "email": email,
                        "chat_count": chat_count,
                        "message_count": message_count
                    })

                return {"status": "success", "users": usage_data}
        except Exception as e:
            return {"status": "Error: " + str(e)}
