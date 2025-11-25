import streamlit as st
import os
import json
import hashlib
import secrets
from PyPDF2 import PdfReader, PdfWriter
import pandas as pd
# subprocess is removed for portability

# --- CONFIGURATION ---
st.set_page_config(page_title="Document Manager", layout="wide")
USER_DB_FILE = "users.json"

# Base Paths
BASE_FOLDER = "D:/H&M"
FOLDERS_CONFIG = {
    "Cash Incentive": {
        "path": "D:/H&M/Cash Incentive Merge",
        "subfolders": ["Invoice", "Tracker", "FCR", "Packing List", "Shipping Bill", "EXP"],
        "pages": {"Invoice": 1, "Tracker": 1, "FCR": 1, "Packing List": 1, "Shipping Bill": 2, "EXP": 1}
    },
    "Bank Document": {
        "path": "D:/H&M/Bank Document Merge",
        "subfolders": ["Shipping Bill", "Invoice", "FCR", "EXP"],
        "pages": {"Shipping Bill": 2, "Invoice": 1, "FCR": 1, "EXP": 1}
    },
    "EPB": {
        "path": "D:/H&M/EPB Merge",
        "subfolders": ["Invoice", "FCR", "Shipping Bill"],
        "pages": {"Invoice": 1, "FCR": 1, "Shipping Bill": 2}
    }
}

# --- AUTHENTICATION FUNCTIONS ---

def hash_password(password, salt=None):
    """Hashes password using a salt for better security."""
    if salt is None:
        salt = secrets.token_hex(16)
    
    salted_password = salt + password
    hashed = hashlib.sha256(str.encode(salted_password)).hexdigest()
    
    return hashed, salt 

def load_users():
    """Loads users from the JSON file."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    try:
        with open(USER_DB_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_user(username, password):
    """Saves a new user with salt to the JSON file."""
    users = load_users()
    if username in users:
        return False
        
    hashed_pass, salt = hash_password(password)
    
    users[username] = {"hash": hashed_pass, "salt": salt}
    
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=4)
    return True

def authenticate(username, password):
    """Checks username and password using the stored salt."""
    users = load_users()
    if username in users and isinstance(users[username], dict) and "hash" in users[username]:
        stored_hash = users[username]["hash"]
        stored_salt = users[username].get("salt")
        
        if not stored_salt:
            return users[username].get("hash") == hashlib.sha256(str.encode(password)).hexdigest()
        
        input_hash, _ = hash_password(password, salt=stored_salt)
        
        return input_hash == stored_hash
    return False

# --- DOCUMENT PROCESSING FUNCTIONS ---

def get_file_path(folder_type, subfolder, order_no, common_name):
    if folder_type == "Cash Incentive" and subfolder == "Packing List":
        filename = f"PackerView-{order_no}-{common_name}.pdf"
    else:
        filename = f"{order_no}-{common_name}.pdf"
    return os.path.join(BASE_FOLDER, subfolder, filename), filename

def check_documents(category, order_nos, common_name):
    config = FOLDERS_CONFIG[category]
    data = []
    missing_log = []
    found_files_map = {}

    for order_no in order_nos:
        row = {"Order No": order_no}
        for sub in config["subfolders"]:
            path, name = get_file_path(category, sub, order_no, common_name)
            if os.path.exists(path):
                row[sub] = "✅"
                found_files_map[(order_no, sub)] = path
            else:
                row[sub] = "❌"
                missing_log.append(f"Order {order_no}: Missing {sub} ({name})")
        data.append(row)
    return pd.DataFrame(data), missing_log, found_files_map

def merge_process(category, order_nos, common_name, found_files_map):
    config = FOLDERS_CONFIG[category]
    output_folder = config["path"]
    os.makedirs(output_folder, exist_ok=True)
    serial = 1
    success_count = 0
    
    merged_output_filename = f"{category}_{common_name}.pdf"
    merged_output_path = os.path.join(output_folder, merged_output_filename)
    
    final_writer = PdfWriter()
    
    for order_no in order_nos:
        order_writer = PdfWriter()
        files_added = False
        
        for sub in config["subfolders"]:
            key = (order_no, sub)
            if key in found_files_map:
                try:
                    reader = PdfReader(found_files_map[key])
                    limit = config["pages"].get(sub, 1)
                    for i in range(min(limit, len(reader.pages))):
                        order_writer.add_page(reader.pages[i])
                    files_added = True
                except:
                    pass
        
        if files_added:
            for page in order_writer.pages:
                final_writer.add_page(page)
            serial += 1
            success_count += 1
            
    if success_count > 0:
        with open(merged_output_path, "wb") as f:
            final_writer.write(f)
            
    return success_count, merged_output_path 

def delete_merged_files(folder_path):
    deleted = 0
    if os.path.exists(folder_path):
        for f in os.listdir(folder_path):
            if f.endswith(".pdf"):
                try:
                    os.remove(os.path.join(folder_path, f))
                    deleted += 1
                except: pass
    return deleted

# --- REFRESH FUNCTION ---
def refresh_app_state():
    """Clears all input fields and resets the search/merge status."""
    # Clear input fields by setting their session state values to empty string
    if 'raw_orders_key' in st.session_state:
        st.session_state['raw_orders_key'] = ""
    if 'common_name_key' in st.session_state:
        st.session_state['common_name_key'] = ""

    # Clear search results and merge status
    keys_to_clear = ['df', 'missing', 'found_map', 'order_list', 'common_name', 'merge_done']
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]
    
    # Removing st.rerun() here as state changes (raw_orders_key and common_name_key) trigger it naturally.

# --- UI PAGES ---

def login_ui():
    st.title("🔒 Sign Up/Login")
    
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            if authenticate(username, password):
                st.session_state['user'] = username
                st.rerun()
            else:
                st.error("Invalid Username or Password")
    
    with tab2:
        new_user = st.text_input("New Username", key="signup_user")
        new_pass = st.text_input("New Password", type="password", key="signup_pass")
        if st.button("Create Account"):
            if new_user and new_pass:
                if save_user(new_user, new_pass):
                    st.success("Account created! Please go to Login tab.")
                else:
                    st.error("Username already exists.")
            else:
                st.warning("Please fill both fields.")

def main_app_ui():
    st.sidebar.write(f"👤 Logged in as: **{st.session_state['user']}**")
    
    if st.sidebar.button("Logout"):
        del st.session_state['user']
        for key in list(st.session_state.keys()):
            if key not in ['user']:
                del st.session_state[key]
        st.rerun()
        
    st.sidebar.divider()

    st.title("📂 Document Automation")
    app_mode = st.sidebar.selectbox("Select Process", ["Cash Incentive", "Bank Document", "EPB"])
    st.header(f"{app_mode} Processing")

    col1, col2 = st.columns([2, 1])
    with col1:
        # Added key for refresh functionality
        raw_orders = st.text_area("Enter Order Numbers (space/newline)", height=100, key='raw_orders_key')
    with col2:
        # Added key for refresh functionality
        common_name = st.text_input("Common Name", key='common_name_key')

    # New row for Search and Refresh buttons
    b_col1, b_col2 = st.columns(2)
    with b_col1:
        if st.button("🔍 Search Documents", use_container_width=True):
            if not raw_orders or not common_name:
                st.error("Inputs required.")
            else:
                order_list = raw_orders.strip().split()
                df, missing, found_map = check_documents(app_mode, order_list, common_name.strip())
                st.session_state['df'] = df
                st.session_state['missing'] = missing
                st.session_state['found_map'] = found_map
                st.session_state['order_list'] = order_list
                st.session_state['common_name'] = common_name.strip()
                st.session_state['merge_done'] = False
                st.rerun()
    with b_col2:
        # Added Refresh button with on_click callback
        st.button("🔄 Refresh Fields", on_click=refresh_app_state, use_container_width=True)

    if 'df' in st.session_state:
        st.subheader("Search Results")
        st.dataframe(st.session_state['df'], use_container_width=True)
        
        if st.session_state['missing']:
            with st.expander("View Missing Files Log"):
                for m in st.session_state['missing']: st.write(m)

        c1, c2 = st.columns(2)
        with c1:
            if st.button("⚡ Merge Files"):
                count, output_path = merge_process(app_mode, st.session_state['order_list'], st.session_state['common_name'], st.session_state['found_map'])
                
                if count > 0:
                    st.success(f"Merged {count} document batches into one file: **{os.path.basename(output_path)}**. File saved to disk.")
                    st.session_state['merge_done'] = True
                else:
                    st.error("No documents were found to merge.")
                
                # Clear search state but keep merge state
                for key in ['df', 'missing', 'found_map', 'order_list', 'common_name']:
                    if key in st.session_state:
                        del st.session_state[key]
                st.rerun()
                
        with c2:
            confirm_delete = st.checkbox("Confirm Deletion", key=f"del_check_{app_mode}")
            
            merge_folder_to_delete = FOLDERS_CONFIG[app_mode]["path"]

            if st.button("🗑️ Delete Merged", disabled=not confirm_delete):
                if confirm_delete:
                    count = delete_merged_files(merge_folder_to_delete)
                    
                    # Streamlit equivalent of a pop-up after delete
                    if count > 0:
                         st.success(f"Successfully deleted {count} merged PDF file(s) from the output folder: {merge_folder_to_delete}")
                    else:
                         st.info(f"No merged PDF files were found to delete in: {merge_folder_to_delete}")
                    
                    st.session_state['merge_done'] = False
                    st.rerun()
                else:
                    st.warning("Please check the 'Confirm Deletion' box first.")

# --- MAIN ENTRY POINT ---

if 'user' not in st.session_state:
    st.session_state['user'] = None

if st.session_state['user'] is None:
    login_ui()
else:
    main_app_ui()
