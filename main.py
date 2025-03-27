from flask import Flask, request, render_template,send_file, jsonify, make_response
from datetime import datetime
from fuzzywuzzy import fuzz, process
import traceback
import requests
import json
import random
import csv
import io
import os
from flask_cors import CORS

#local libraries
from database import Database
from file_control import File_Control
from collector import Collector
from process import Process
from euclid import Euclid
from graph import Graph
from assist import Assist
from rag import RAG
from ads import Ads
from auth import auth

database=Database()
collections=Euclid()

app = Flask(__name__)
CORS(app)




#--------------------------------------------------------------------------------------------------------------
# AUTH AND ACCOUNT MANAGEMENT

# Pinging the system
@app.route('/ping', methods=['GET'])
def ping():
    return {'status': 'running'}
  
# Register a new account
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    user_type = data.get('user_type')
    code = "00000"
    password = data.get('password')
    phone = data.get('phone')
    lawfirm_name="individual"
    isadmin = 'false'

    if user_type=="org":
        lawfirm_name = data.get('lawfirm_name')
        isadmin ='true'
    result = database.add_user(name, email, phone, user_type, code, lawfirm_name, password, isadmin)
    
    # If user resgistration is successfull, generate a token
    if result.get("status") == "success":
      user_id = result.get("user")
      token = auth.generate_token(user_id, isadmin)
      return{"status": "success", "user": user_id, "token": token}
    
    return result

# Login to account
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = database.login(email, password)
    if user.get("status") == "success":
      user_id = user.get("user")
      isadmin = database.get_isadmin(user_id)
      token = auth.generate_token(user_id, isadmin)
      return {"status": "success", "user": user_id, "token": token}
    return user

#Editor login to account
@app.route('/editorlogin', methods=['POST'])
def editor_login():
  data = request.get_json()
  email=data.get('email')
  password=data.get('password')
  log=database.login(email,password)
  return log

# Superuser login to account
@app.route('/superuserlogin', methods=['POST'])
def superuser_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    result = database.superuser_login(email, password)
    
    if result.get("status") == "success":
      admin_id = result.get("admin_id")
      if admin_id is None:
        return {"status": "Error: Superuser login failed. Admin ID is missing"}, 400
      token = auth.generate_token(None, False, admin_id)
      return {"status": "success", "admin_id": admin_id, "token": token}
    
    return result
    

# Add new superuser
@app.route('/add_superuser', methods=['POST'])
@auth.jwt_required(required_role="superuser") # Added decorator
def add_superuser(decoded_token): # Added decoded_token parameter
    data = request.get_json()
    # admin_id = data.get('admin_id') Removed manual admin_id(it's now handled by decorator)
    admin_id = decoded_token.get("admin_id")
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    result = database.add_superuser(admin_id, name, email, password)
    return result

# Change superuser password
@app.route('/change_superuser_password', methods=['POST'])
@auth.jwt_required(required_role="superuser")
def change_superuser_password(decoded_token):
    data = request.get_json()
    admin_id = decoded_token['admin_id']
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    result = database.change_superuser_password(admin_id, old_password, new_password)
    return result

# Get all superusers
@app.route('/get_superusers', methods=['GET'])
@auth.jwt_required(required_role="superuser")
def get_superusers(decoded_token):
    admin_id = decoded_token["admin_id"]
    result = database.get_superusers(admin_id)
    return result

# Delete a superuser
@app.route('/delete_superuser', methods=['DELETE'])
@auth.jwt_required(required_role="superuser")
def delete_superuser(decoded_token):
    data = request.get_json()
    admin_id = decoded_token['admin_id']
    admin_id_to_delete_id = data.get('admin_id_to_delete')
    
    result = database.delete_superuser(admin_id, admin_id_to_delete_id)
    return result



# Change Password
@app.route('/password', methods=['POST'])
@auth.jwt_required()
def change_password(decoded_token):
  data = request.get_json()
  user_id = decoded_token['user_id']
  if decoded_token["user_id"] != user_id:
    return {'status': 'Unauthorized access!'}, 403
  old_password = data.get('old_password')
  new_password = data.get('new_password')
  
  logged_in_user = request.headers.get("user_id")
  if logged_in_user != user_id:
    return {'status': 'Unauthorized access!'}, 403
  
  passwd = database.change_password(user_id, old_password, new_password)
  return passwd

#view user profile
@app.route('/user_profile', methods=['GET'])
@auth.jwt_required()
def view_user_profile(decoded_token):
  user_id = request.args.get('user_id')
  
  if user_id != decoded_token["user_id"] and decoded_token.get("isadmin") != "true":
    return {'status': 'Unauthorized access!'}, 403
  profile = database.user_profile(user_id)
  return profile

#view all users profile (superusers only)
@app.route('/allusers', methods=['GET'])
@auth.jwt_required(required_role="superuser")
def view_all_profiles(decoded_token):
  admin_id = decoded_token['admin_id']
  
  # admin_check = database.get_superusers(admin_id)
  # if admin_check.get("status") != "success":
  #   return {"status": "Unauthorized access!"}, 403
  
  users = database.profiles()
  return {'users': users}

# Subscribe a user
@app.route('/subscribe_user', methods=['POST'])
@auth.jwt_required(required_role="superuser")
def subscribe_user(decoded_token):
  data = request.get_json()
  user_id=data.get('user_id')
  admin_id=decoded_token.get('admin_id')
  next_date=data.get('next_date')
  
      # Ensure requester is a superuser(now handled by decorator)
  # superuser_check = database.get_superusers(admin_id)
  # if superuser_check.get("status") != "success":
  #     return {"status": "Unauthorized access! Superusers only."}, 403
    
  update=database.subscribe_user(admin_id, user_id, next_date)
  users=database.profiles()
  return {'status':update,'users':users}

# Subscribe an organisation
@app.route('/subscribe_org', methods=['POST'])
@auth.jwt_required(required_role="superuser")
def subscribe_orginisation(decoded_token):
  data = request.get_json()
  admin_id=decoded_token.get('admin_id')
  code = data.get('code')
  next_date=data.get('next_date')
  
  # # Ensure requester is a superuser
  # superuser_check = database.get_superusers(admin_id)
  # if superuser_check.get("status") != "success":
  #     return {"status": "Unauthorized access! Superusers only."}, 403
    
  update=database.subscribe_org(admin_id, code,next_date)
  users=database.profiles()
  return {'status': update,'users':users}

# Delete a user profile
@app.route('/delete_user', methods=['DELETE'])
@auth.jwt_required(required_role="superuser")
def delete_profile(decoded_token):
  admin_id = decoded_token.get('admin_id') # Superuser ID
  user_id=request.args.get('user_id')
  
  # superuser_check = database.get_superusers(admin_id)
  # if superuser_check.get("status") != "success":
  #   return {"status": "Unauthorized access! Superusers only."}, 403
  
  op = database.delete_user(admin_id, user_id)
  users=database.profiles()
  return {'status': op, 'users':users}


@app.route('/user_usage', methods=['GET'])
@auth.jwt_required()
def get_user_usage(decoded_token):
  user_id = request.args.get('user_id')
  if user_id != decoded_token["user_id"] and decoded_token.get("isadmin") != "true":
    return jsonify ({'status': 'Unauthorized access!'}), 403
  result = database.get_user_usage(user_id)
  return result

@app.route('/all_users_usage', methods=['GET'])
@auth.jwt_required(required_role="superuser")
def get_all_users_usage(decoded_token):
  
  result = database.get_all_users_usage(decoded_token["admin_id"])
  return result

#---------------------------------------------------------------------------------------------------------------

# ADMIN USER MANAGEMENT

# Admin adds a new user to their lawfirm
@app.route('/admin_add_user', methods=['POST'])
@auth.jwt_required(required_role="org_admin") # Added decorator
def admin_add_user(decoded_token):
    data = request.get_json()
    admin_id = decoded_token['admin_id']
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')
    
    result = database.admin_add_user(admin_id, name, email, phone, password)
    
    if result.get('status') == 'success':
        # Get updated list of users in the organization
        org_users = database.get_org_users(admin_id)
        return {'status': 'success', 'user': result.get('user'), 'org_users': org_users.get('users',[])}
    else:
        return result
    
# Admin deletes a user from their lawfirm
@app.route('/admin_delete_user', methods=['DELETE'])
@auth.jwt_required(required_role="org_admin")
def admin_delete_user(decoded_token):
    data = request.get_json()
    admin_id = decoded_token.get('admin_id')
    user_id_to_delete = data.get('user_id')
    
    delete = database.admin_delete_user(admin_id, user_id_to_delete)
    if delete.get('status') == 'success':
        # Get updated list of users in the organization
        org_users = database.get_org_users(admin_id)
        return {'status': 'success', 'org_users': org_users.get('users',[])}
    else:
        return delete
    
# Admin views all users in their lawfirm
@app.route('/org_users', methods=['GET'])
@auth.jwt_required(required_role="org_admin")
def get_org_users(decoded_token):
    admin_id = decoded_token.get('admin_id')
    result = database.get_org_users(admin_id)
    results=[item for item in result['users'] if item['user_id']!=admin_id]
    return results
    
# Admin updates a user's status in their lawfirm
@app.route('/admin_update_user_status', methods=['PATCH'])
@auth.jwt_required(required_role="org_admin")
def admin_update_user_status(decoded_token):
    data = request.get_json()
    admin_id = decoded_token['admin_id']
    user_id = data.get('user_id')
    new_status = data.get('status')
    
    # Ensure admin belongs to the same organization
    admin_info = database.user_profile(admin_id)
    user_info = database.user_profile(user_id)
    
    if admin_info.get("code") != user_info.get("code"):
        return {'status': 'Unauthorized action! Users must be in the same organization.'}, 403
    
    update = database.admin_update_user_status(admin_id, user_id, new_status)
    
    if update.get('status') == 'success':
        # Get updated list of users in the organization
        org_users = database.get_org_users(admin_id)
        return {'status': 'success', 'org_users': org_users.get('users',[])}
    else:
        return update






#------------------------------------------CORE METHODS---------------------------


#add a chat
@app.route('/add_chat', methods=['POST'])
@auth.jwt_required()
def add_chat(decoded_token):
  data = request.get_json()
  name=data.get('name')
  user = decoded_token["user_id"]
  add=database.add_chat(user, name)
  chats=database.chats(user)
  return {"status":add,"chats":chats}

#delete a chat
@app.route('/deli_chat', methods=['GET'])
@auth.jwt_required()
def deli_chat(decoded_token):
  chat=request.args.get('chat_id')
  # user=request.args.get('user_id')
  user = decoded_token["user_id"]
  deli=database.deli_chat(chat)
  chats=database.chats(user)

  return {"status":deli["status"],"chats":chats}

#retrieve all chats belonging to a user
@app.route('/chats', methods=['GET'])
@auth.jwt_required()
def collect_chats(decoded_token):
  user=decoded_token['user_id']
  chats=database.chats(user)
  tables=collections.tables()
  table_data=[]
  tables_list=[]
  for col in tables:
    tables_list.append(col)

  return {"chats":chats,"tables":tables_list}

#retrieve all chats belonging to a user
@app.route('/messages', methods=['GET'])
@auth.jwt_required()
def collect_messages(decoded_token):
  chat=request.args.get('chat_id')
  messages=database.messages(chat)

  return {"messages":messages}

#playground
@app.route('/play', methods=['POST'])
@auth.jwt_required()
def run_playground(decoded_token):
  data = request.get_json()
  chat = data.get('chat_id')
  user = decoded_token['user_id']
  prompt = data.get('prompt')
  tool = data.get('tool')
  rag= RAG(collections)
  # Check if there is a valid chat or it's a new one
  if chat == '' or chat is None:
    name = rag.naming(prompt)
    add = database.add_chat(user, name)
    chat = add['chat']
  # Execute
  try:
    document=''
    if 'document' in data:
      document=data.get('document')
    history = database.messages(chat)
    answer, sources = rag.single_step(tool, prompt, history, 3, 3)
    ads=Ads()
    ad=ads.random_advertiser()
  except Exception as e:
    traceback.print_exc()
    p={"answer":[{"type":"paragraph","data":"Error generating content, please try again. If the error persist create a new workspace."}],"sources":[], "citations":[]}
    answer=json.dumps(p)
    sources=[]
    ad={}

  # Add answer to database
  add = database.add_message(chat, user, str(answer), prompt)
  messages = database.messages(chat)
  chats = database.chats(user)

  return {"messages": messages, "chats": chats, "current": chat,'ads':ad}

#playground
@app.route('/assist', methods=['POST'])
@auth.jwt_required()
def run_assist(decoded_token):
  data = request.get_json()
  chat = data.get('chat_id')
  user = decoded_token['user_id']
  prompt = data.get('prompt')
  table = data.get('tool')
  assist=Assist(collections)
  rag=RAG(collections)
  # Check if there is a valid chat or it's a new one
  if chat == '' or chat is None:
    name = rag.naming(prompt)
    add = database.add_chat(user, name)
    chat = add['chat']
  #check for billing
  billing=database.billing(user)
  if billing['status']!='success':
    messages = database.messages(chat)
    chats = database.chats(user)
    return {"messages": messages, "chats": chats, "current": chat,"warning":billing['status']}
  # Execute
  try:
    history = database.messages(chat)
    answer, sources = assist.run(table, prompt, history)
  except Exception as e:
    traceback.print_exc()
    p={"answer":[{"type":"paragraph","data":"Error generating content, please try again. If the error persist create a new workspace."}],"sources":[], "citations":[]}
    answer=json.dumps(p)
    sources=[]

  # Add answer to database
  add = database.add_message(chat, user, str(answer), prompt)
  messages = database.messages(chat)
  chats = database.chats(user)

  return {"messages": messages, "chats": chats, "current": chat}


#upload files for GPT
@app.route('/cloudupload', methods=['POST'])
@auth.jwt_required()
def upload_files_gpt(decoded_token):
  chat = request.form.get('chat_id')
  transcript=[]
  files = request.files.getlist('files')
  if len(files) == 0:
    return {"status":"No file part"}
  # Create a temporary directory
  path="../files/uploads/"+chat+"/"
  folder=create_dir(path)
  if folder['message']=='error':
    return {"status":"Error creating folder"}
  # Save each file to the temporary directory
  for file in files:
    if file.filename == '':
      continue
    filename = os.path.join(path, file.filename)
    file.save(filename)
    name=file.filename
    '''
    if name.endswith('.pdf'):
      new_path="./files/pdf_images/"+chat+"/"
      folder=create_dir(new_path)
      t=File()
      t.pdf_to_images(name,path,new_path)
      vis=Vision()
      pages=vis.pdf_vision(name, new_path)
      print(pages)'''
  #upload files
  nodes=generate_tree(path)
  return {"status":"success",'nodes':nodes}

@app.route('/source', methods=['GET'])
@auth.jwt_required()
def get_source(decoded_token):
  tool=request.args.get('tool')
  name=request.args.get('name')
  if tool=="assistant":
    return "Load html content"
  elif tool=="web":
    return {"url":name}
  elif tool=="documents":
    chat=request.args.get('chat_id')
    file="../files/uploads/"+chat+"/"+name
    return send_file(file, as_attachment=False)
  else:
    #search for the document
    file=search_file('../files/closed/'+tool+'/',name)
    if file:
      return send_file(file, as_attachment=False)
    else:
      return "File not found"


@app.route('/get_file', methods=['GET'])
@auth.jwt_required()
def get_pdf(decoded_token):
  file_id=request.args.get('file_id')
  filename=request.args.get('filename')
  table_id=request.args.get('table_id')
  table=request.args.get('table')
  file_path='../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename
  if File_Control.check_path(file_path):
    return send_file(file_path, as_attachment=False)
  else:
    return jsonify({'error': 'Document does not exist'}), 400

@app.route('/get_created_file', methods=['GET'])
@auth.jwt_required()
def get_created_pdf(decoded_token):
  filename=request.args.get('filename')
  file_path='../documents_created/'+filename
  if File_Control.check_path(file_path):
    return send_file(file_path, as_attachment=False)
  else:
    return jsonify({'error': 'Document does not exist'}), 400


#--------------------------------------------------EDITOR MODE METHODS




#Load all the tables currently created
@app.route('/tables', methods=['GET'])
def tables():
  #check if tables object exist
  if File_Control.check_path('../tables/') and File_Control.check_path('../tables/root.pkl'):
    tables=File_Control.open('../tables/root.pkl')
    if len(tables)>0:
      files=File_Control.open('../tables/files.pkl')
      for table in tables:
        processed_files=[item for item in files if item['table']==table['name']]
        table['count']=len(processed_files)
  else:
    #create folder
    File_Control.create_path('../tables/')
    tables=[]
    File_Control.save('../tables/root.pkl',tables)
    File_Control.save('../tables/files.pkl',tables)
  return {"tables":tables}

#create a table
@app.route('/add_table', methods=['POST'])
def create_table():
  data = request.get_json()
  name=data.get('name')
  type=data.get('type')
  #view what is in the tables
  tables=File_Control.open('../tables/root.pkl')
  vector=Euclid()
  add=vector.create_table(name)
  if add=='success':
    table_id=str(random.randint(1000,9999))
    table={"id":table_id,"name":name,"type":type,'count':0}
    tables.append(table)
    File_Control.save('../tables/root.pkl',tables)
    files=[]
    File_Control.save('../tables/'+name+'-'+table_id+'.pkl',files)
    File_Control.create_path('../temp/'+name+'-'+table_id+'/')
    File_Control.create_path('../data/'+name+'-'+table_id+'/')

    return {"result":"success","tables":tables}
  else:
    return {"result":"error creating vector database table, check table name","tables":tables}

#delete a table
@app.route('/delete_table', methods=['GET'])
def delete_table():
  table=request.args.get('id')
  name=request.args.get('name')
  tables=File_Control.open('../tables/root.pkl')
  vector=Euclid()
  dele=vector.delete_table(name)
  if dele=='success':
    files=File_Control.open('../tables/files.pkl')
    new_files=[item for item in files if item['table_id'] != table]
    new_tables=[item for item in tables if item['id'] != table]
    File_Control.save('../tables/root.pkl',new_tables)
    File_Control.save('../tables/files.pkl',new_files)
    File_Control.delete_file('../tables/'+name+'-'+table+'.pkl')
    tables=File_Control.open('../tables/root.pkl')
    File_Control.delete_path('../temp/'+name+'-'+table+'/')
    File_Control.delete_path('../data/'+name+'-'+table+'/')

    return {'tables':tables}
  else:
    return {'tables':tables}


#file upload
@app.route('/upload', methods=['POST'])
def upload_files():
  table_id = request.form.get('id')
  name = request.form.get('name')
  files = request.files.getlist('files')
  if len(files) == 0:
    return {'result':'zero'}
  path='../temp/'+name+'-'+table_id+'/'
  uploaded_files=[]
  n=0
  for file in files:
    if file.filename == '':
      continue
    file_id=str(random.randint(1000000000,9999999999))
    filename = os.path.join(path, file_id+'-'+file.filename)
    file.save(filename)
    uploaded_files.append({'filename':file.filename, 'file_id': file_id, 'table_id': table_id, 'table':name,'isProcessed':False})
    n=n+1

  other_files=File_Control.open('../tables/files.pkl')
  other_files.extend(uploaded_files)
  File_Control.save('../tables/files.pkl',other_files)
  tables=File_Control.open('../tables/root.pkl')
  table=next(item for item in tables if item['id'] == table_id)
  tables=[item for item in tables if item['id'] != table_id]
  table['count']=n
  tables.append(table)
  File_Control.save('../tables/root.pkl',tables)

  return {'result':'success','files':other_files}

#Load all unprocessed documents currently created
@app.route('/files', methods=['GET'])
def unproc_files():
  #check if files object exist
  tables=File_Control.open('../tables/root.pkl')
  if File_Control.check_path('../tables/files.pkl'):
    files=File_Control.open('../tables/files.pkl')
  else:
    #create folder
    File_Control.create_path('../tables/')
    files=[]
    File_Control.save('../tables/files.pkl',files)
  files=files[-100:]
  return {'files':files,'tables':tables}

#delete an unprocessed file
@app.route('/delete_unproc_file', methods=['GET'])
def delete_file_unprocessed():
  file_id=request.args.get('file_id')
  filename=request.args.get('filename')
  table_id=request.args.get('table_id')
  table=request.args.get('table')
  files=File_Control.open('../tables/files.pkl')
  if File_Control.check_path('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl'):
    file=File_Control.open('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
    new_files=[item for item in files if item['file_id'] != file_id]
    vector=Euclid()
    deli=vector.delete(table,'file_id',file_id)
    if deli=='success':
      File_Control.save('../tables/files.pkl',new_files)
      File_Control.delete_file('../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename)
      File_Control.delete_file('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
      new_files=files[-100:]
      return {'files':new_files}
    else:
      files=files[-100:]
      return {'files':files}
  else:
    new_files=[item for item in files if item['file_id'] != file_id]
    File_Control.save('../tables/files.pkl',new_files)
    File_Control.delete_file('../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename)
    new_files=files[-100:]
    return {'files':new_files}

#delete a file
@app.route('/delete_file', methods=['GET'])
def delete_file():
  file_id=request.args.get('file_id')
  filename=request.args.get('filename')
  table_id=request.args.get('table_id')
  table=request.args.get('table')
  files=File_Control.open('../tables/files.pkl')
  file=File_Control.open('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
  new_files=[item for item in files if item['file_id'] != file_id]
  vector=Euclid()
  deli=vector.delete(table,'file_id',file_id)
  cite=file['citation']
  graph=Graph()
  dele_graph=graph.delete_node(cite)
  if deli=='success' and dele_graph=='success':
    File_Control.save('../tables/files.pkl',new_files)
    File_Control.delete_file('../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename)
    File_Control.delete_file('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
    return {'files':new_files}
  else:
    return {'files':files}

#process a file
@app.route('/proc_file', methods=['GET'])
def proc_file():
  file_id=request.args.get('file_id')
  filename=request.args.get('filename')
  table_id=request.args.get('table_id')
  table=request.args.get('table')
  file_path='../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename
  collect=Collector()
  #process document using the AI
  proc=Process()
  tables=File_Control.open('../tables/root.pkl')
  tab=next(item for item in tables if item['id'] == table_id)
  if tab['type']=='ruling':
    if filename.lower().endswith('.pdf'):
      document=collect.pdf_raw(file_path)
    elif filename.lower().endswith('.docx'):
      document=collect.collect_docx(file_path)
    run=proc.court_proc(table, table_id, file_id, filename, document)
  elif tab['type']=='legislation':
    if filename.lower().endswith('.htm') or filename.lower().endswith('.html'):
      document=collect.html_styles(file_path)
      run=proc.legislation(table, table_id, file_id, filename, document)
    elif filename.lower().endswith('.pdf'):
      document=collect.pdf_raw(file_path)
      run=proc.legislation(table, table_id, file_id, filename, document)
    elif filename.lower().endswith('.docx'):
      document=collect.docx_styles(file_path)
      run=proc.legislation(table, table_id, file_id, filename, document)
  else:
    #other methods of processing documents
    run={'result':'method for processing does not exist','content':{}}
  #updated status
  files=File_Control.open('../tables/files.pkl')
  if run['result']=='success':
    #add to table
    File_Control.save('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl',run['content'])
    next(item for item in files if item['file_id'] == file_id)['isProcessed'] = True
    File_Control.save('../tables/files.pkl',files)

  else:
    print(run['result'])

  files=File_Control.open('../tables/files.pkl')
  files=files[-100:]
  return {'result':run['result'],'files':files}

#open a file
@app.route('/open_file', methods=['GET'])
def open_file():
  file_id=request.args.get('file_id')
  filename=request.args.get('filename')
  table_id=request.args.get('table_id')
  table=request.args.get('table')
  file=File_Control.open('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
  tables=File_Control.open('../tables/root.pkl')
  tab=next(item for item in tables if item['id'] == table_id)
  cite=file['citation']
  graph=Graph()
  n=graph.search(cite)
  file_path='../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename
  collect=Collector()
  if filename.lower().endswith('.pdf'):
    document=collect.pdf_raw(file_path)
  elif filename.lower().endswith('.docx'):
    document=collect.docx_styles(file_path)
  elif filename.lower().endswith('.htm') or filename.lower().endswith('.html'):
    document=collect.html_styles(file_path)
  file['raw']=document
  file['sections']=[]
  #print(file)

  return {'file':file,'type':tab['type'],'graph':n}

#load all processed files
@app.route('/load_processed', methods=['GET'])
def load_all_processed_files():
  table1=request.args.get('table')
  #check if files object exist
  tables=File_Control.open('../tables/root.pkl')
  if File_Control.check_path('../tables/files.pkl'):
    files=File_Control.open('../tables/files.pkl')
  else:
    #create folder
    File_Control.create_path('../tables/')
    files=[]
    File_Control.save('../tables/files.pkl',files)

  processed_files=[]
  for file in files:
    if(file['isProcessed']==True):
      file_id=file['file_id']
      filename=file['filename']
      table_id=file['table_id']
      table=file['table']
      cont=File_Control.open('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
      processed_files.append({'filename':filename, 'file_id': file_id, 'table_id': table_id, 'table':table, 'citation':cont['citation']})
  #load files from the provided table
  processed_files1=[item for item in processed_files if item['table']==table1]
  all_files=processed_files1[-20:]
  return {'files':all_files,'tables':tables}


#save a file for viewing later
@app.route('/save_file', methods=['POST'])
@auth.jwt_required()
def save_file_as_bookmark(decoded_token):
  data = request.get_json()
  user_id=data.get('user_id')
  file_id=data.get('file_id')
  filename=data.get('filename')
  table_id=data.get('table_id')
  table=data.get('table')
  file=File_Control.open('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
  tables=File_Control.open('../tables/root.pkl')
  tab=next(item for item in tables if item['id'] == table_id)
  cite=file['citation']
  save=database.save_doc(user_id, file_id, filename, table_id, table, cite)

  return save


#save a file for viewing later
@app.route('/load_saved_files', methods=['GET'])
def load_saved_files():
  user_id=request.args.get('user_id')
  saved=database.load_saved(user_id)

  return saved

#delete a file saved for viewing later
@app.route('/delete_saved_file', methods=['POST'])
@auth.jwt_required()
def delete_saved_file(decoded_token):
  data = request.get_json()
  user_id=decoded_token['user_id']
  file_id=data.get('file_id')
  deli=database.deli_saved(user_id, file_id)

  return deli

#section processing
@app.route('/section_proc', methods=['GET'])
def process_section():
  file_id=request.args.get('file_id')
  filename=request.args.get('filename')
  table_id=request.args.get('table_id')
  table=request.args.get('table')
  section_number=request.args.get('section_number')
  file=File_Control.open('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
  section=next(item for item in file['sections'] if item['section_number'] == section_number)
  proc=Process()
  run=proc.section_process(section)

  return {'section':run}

#section processing
@app.route('/regenerate', methods=['GET'])
def document_regenerate():
  file_id=request.args.get('file_id')
  filename=request.args.get('filename')
  table_id=request.args.get('table_id')
  table=request.args.get('table')
  file_path='../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename
  collect=Collector()
  #process document using the AI
  proc=Process()
  document=collect.pdf_raw(file_path)
  run=proc.court_proc(table, table_id, file_id, filename, document)
  files=File_Control.open('../tables/files.pkl')
  vector=Euclid()
  deli=vector.delete(table,'file_id',file_id)
  if deli=='success':
    if run['result']=='success':
      #add to table
      File_Control.save('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl',run['content'])
      return {'result':run['result'],'file':run['content']}
    else:
      return {'result':'Error re-generating from the AI'}
  else:
    return {'result':'error deleting vector file'}

#upload changes to sections
@app.route('/upload_changes', methods=['POST'])
def upload_changes():
  data = request.get_json()
  file_id=data.get('file_id')
  filename=data.get('filename')
  table_id=data.get('table_id')
  table=data.get('table')
  document=data.get('document')
  vector=Euclid()
  deli=vector.delete(table,'file_id',file_id)
  if deli=='success':
    proc=Process()
    run=proc.update_legi(table, table_id, file_id, filename, document)
    if run=='success':
      File_Control.delete_file('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
      File_Control.save('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl',document)
      return {'result':'success'}
    else:
      return {'result':'Error embedding and adding to vector database'}
  else:
    return {'result':'Error deleting records from vector database'}

#do a raw search of the euclid database
@app.route('/raw_search', methods=['POST'])
def raw_search():
  data = request.get_json()
  table=data.get('table')
  query=data.get('query')
  vector=Euclid()
  r=vector.search(table,query,10)

  return {'documents':r}

#do a raw search of the euclid database
@app.route('/typing_search', methods=['GET'])
def typing_search():
  query=request.args.get('query')
  files=File_Control.open('../tables/files.pkl')
  processed_files=[]
  for file in files:
    if(file['isProcessed']==True):
      file_id=file['file_id']
      filename=file['filename']
      table_id=file['table_id']
      table=file['table']
      cont=File_Control.open('../data/'+table+'-'+table_id+'/'+file_id+'-'+filename+'.pkl')
      processed_files.append({'filename':filename, 'file_id': file_id, 'table_id': table_id, 'table':table, 'citation':cont['citation']})
  citations = [(file['citation'], file) for file in processed_files]
  matches = process.extract(query, [citation[0] for citation in citations], limit=20)
  matched_files=[]
  for file in matches:
    full=next(f for f in processed_files if f['citation']==file[0])
    matched_files.append(full)

  return jsonify({'documents':matched_files})

#deploy all documents into graph
@app.route('/deploy_graph', methods=['GET'])
def deploy_all_documents_to_graph():
  #check if files object exist
  tables=File_Control.open('../tables/root.pkl')
  files=File_Control.open('../tables/files.pkl')
  print('running deployment')
  documents=[]
  for file in files:
    type=next(item['type'] for item in tables if item['id'] == file['table_id'])
    file['type']=type
    documents.append(file)

  graph=Graph()
  n=graph.create_graph(documents)
  print('Done deploying')
  return {'result':'success'}

#deploy all documents into graph
@app.route('/show_graph', methods=['GET'])
def show_react_graph():
  graph=Graph()
  flow=graph.graph_data()
  return flow

#------------
if __name__=='__main__':
    app.run(host='0.0.0.0',port='8080')

