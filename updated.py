import streamlit as st
import os
import json
import hashlib
import secrets
from PyPDF2 import PdfReader, PdfWriter
import platform
import string
import ctypes
from collections import defaultdict

# --- CONFIGURATION ---
USER_DB_FILE = "users.json"
MERGE_FOLDER_CASH = "D:/H&M/Cash Incentive Merge"
MERGE_FOLDER_BANK = "D:/H&M/Bank Document Merge"
MERGE_FOLDER_EPB = "D:/H&M/EPB Merge"

CASH_CONFIG = {
    "SUB_FOLDERS": ["Invoice", "Tracker", "FCR", "Packing List", "Shipping Bill", "EXP"],
    "PAGE_LIMITS": {"Invoice": 1, "Tracker": 1, "FCR": 1, "Packing List": 1, "Shipping Bill": 2, "EXP": 1},
    "MERGE_FOLDER": MERGE_FOLDER_CASH,
    "TITLE": "Cash Incentive Process"
}

BANK_CONFIG = {
    "SUB_FOLDERS": ["Shipping Bill", "Invoice", "FCR", "EXP"],
    "PAGE_LIMITS": {"Shipping Bill": 2, "Invoice": 1, "FCR": 1, "EXP": 1},
    "MERGE_FOLDER": MERGE_FOLDER_BANK,
    "TITLE": "Bank Document Process"
}

EPB_CONFIG = {
    "SUB_FOLDERS": ["Invoice", "FCR", "Shipping Bill"],
    "PAGE_LIMITS": {"Invoice": 1, "FCR": 1, "Shipping Bill": 2},
    "MERGE_FOLDER": MERGE_FOLDER_EPB, 
    "TITLE": "EPB Process"
}

# --- AUTHENTICATION & MOCK DB FUNCTIONS ---

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    salted_password = salt + password
    hashed = hashlib.sha256(str.encode(salted_password)).hexdigest()
    return hashed, salt 

def load_users():
    if not os.path.exists(USER_DB_FILE):
        return {}
    try:
        with open(USER_DB_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_user(username, password, role, first_login_required=True):
    users = load_users()
    if username in users:
        return False
    hashed_pass, salt = hash_password(password)
    users[username] = {
        "hash": hashed_pass,
        "salt": salt,
        "role": role,
        "first_login_required": first_login_required
    }
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=4)
    return True

def update_user_password(username, new_password):
    users = load_users()
    if username not in users:
        return False
    hashed_pass, salt = hash_password(new_password)
    users[username]["hash"] = hashed_pass
    users[username]["salt"] = salt
    users[username]["first_login_required"] = False
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=4)
    return True

def authenticate(username, password, role):
    users = load_users()
    if username in users:
        user_data = users[username]
        if user_data.get("role") != role:
            return False, False, None
        
        stored_hash = user_data["hash"]
        stored_salt = user_data.get("salt")
        
        input_hash, _ = hash_password(password, salt=stored_salt)
            
        if input_hash == stored_hash:
            return True, user_data.get("first_login_required", False), user_data.get("role")
        
    return False, False, None

# --- FULL DRIVE SCAN FUNCTIONS (RUNS LOCALLY ON THE HOST MACHINE) ---

def get_drive_roots():
    """Identifies local drive roots for scanning."""
    roots = []
    system = platform.system()

    if system == "Windows":
        drives = ['%s:' % d for d in string.ascii_uppercase]
        for drive in drives:
            try:
                if ctypes.windll.kernel32.GetDriveTypeW(drive + os.sep) == 3:
                    roots.append(drive + os.sep)
            except:
                continue
    elif system in ["Linux", "Darwin"]:
        roots = ['/', '/mnt', '/Volumes', '/media']
        
    return [r for r in roots if os.path.exists(r) and os.access(r, os.R_OK)]

def check_documents_full_scan(order_nos, common_name, sub_folders):
    """
    PERFORMS A FULL DRIVE SCAN for the required documents.
    Note: This is a slow, blocking operation.
    """
    missing_files, found_files = {}, {}
    required_files = {} 
    
    for order_no in order_nos:
        for folder in sub_folders:
            file_name = f"{order_no}-{common_name}.pdf"
            if folder == "Packing List" and "Packing List" in sub_folders:
                file_name = f"PackerView-{order_no}-{common_name}.pdf"
            required_files[(order_no, folder)] = file_name
            missing_files[(order_no, folder)] = file_name

    roots = get_drive_roots()
    items_to_check = required_files.copy() 

    for root in roots:
        if not items_to_check:
            break
            
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=None):
            if not items_to_check:
                break
            
            current_folder_name = os.path.basename(dirpath)
            
            if current_folder_name in sub_folders:
                for (order_no, folder), file_name in list(items_to_check.items()):
                    if folder == current_folder_name and file_name in filenames:
                        file_path = os.path.join(dirpath, file_name)
                        found_files[(order_no, folder)] = file_path
                        
                        if (order_no, folder) in missing_files:
                            del missing_files[(order_no, folder)]
                        del items_to_check[(order_no, folder)]
                        
            # Optimization: Skip deep system directories
            if platform.system() == "Windows" and any(sys_dir in dirpath.lower() for sys_dir in ['\\windows', '\\$recycle.bin', '\\system volume information']):
                dirnames[:] = []
            elif platform.system() != "Windows" and any(sys_dir in dirpath.lower() for sys_dir in ['/proc', '/sys', '/dev', '/run']):
                dirnames[:] = []

    return found_files, missing_files


# --- CORE LOGIC FUNCTIONS ---

def merge_documents(found_files_map, config, common_name, order_nos):
    """Merges found documents based on configuration."""
    merge_folder = config["MERGE_FOLDER"]
    page_limits = config["PAGE_LIMITS"]
    sub_folders = config["SUB_FOLDERS"]
    
    os.makedirs(merge_folder, exist_ok=True)
    
    final_writer = PdfWriter()
    success_count = 0
    
    for order_no in order_nos:
        order_writer = PdfWriter()
        files_added = False
        
        for sub in sub_folders:
            key = (order_no, sub)
            if key in found_files_map:
                try:
                    reader = PdfReader(found_files_map[key])
                    limit = page_limits.get(sub, 1)
                    for i in range(min(limit, len(reader.pages))):
                        order_writer.add_page(reader.pages[i])
                    files_added = True
                except Exception as e:
                    st.error(f"Error reading PDF {found_files_map[key]}: {e}")
        
        if files_added:
            for page in order_writer.pages:
                final_writer.add_page(page)
            success_count += 1
            
    if success_count > 0:
        process_name = config["TITLE"].split()[0]
        merged_output_filename = f"MERGED_{process_name}_{common_name}.pdf" 
        merged_output_path = os.path.join(merge_folder, merged_output_filename)
        
        try:
            with open(merged_output_path, "wb") as f:
                final_writer.write(f)
            
            st.session_state["merged_output_path"] = merged_output_path
            st.success(f"Merged {success_count} document batches into one file: **{merged_output_filename}**")
            st.info(f"File saved to: `{merge_folder}`")
            return merged_output_path
        except Exception as e:
            st.error(f"Failed to save merged file: {e}")
            return None
    else:
        st.warning("No complete document batches found to merge.")
        return None

# --- STATE MANAGEMENT CALLBACKS ---

def refresh_process_fields():
    """
    Clears all input fields and scan results for the current process screen.
    Streamlit automatically reruns the script after this function completes.
    """
    # 1. Clear scan/merge results
    if "found_files_map" in st.session_state:
        st.session_state["found_files_map"] = {}
    if "missing_files" in st.session_state:
        st.session_state["missing_files"] = {}
    if "merged_output_path" in st.session_state:
        st.session_state["merged_output_path"] = ""
    
    # 2. Delete the widget keys to force them to be empty on rerun
    if "order_nos_text" in st.session_state:
        del st.session_state["order_nos_text"]
    if "common_name_input" in st.session_state:
        del st.session_state["common_name_input"]
    
    # 3. REMOVED st.rerun() to fix the error/warning. Streamlit automatically reruns.

# --- STREAMLIT UI SCREENS ---

def show_login_signup_screen():
    st.title("📄 Authentication")
    
    tab1, tab2 = st.tabs(["Login", "Sign Up"])

    with tab1:
        st.header("Login")
        
        login_user = st.text_input("Username:", key="login_user")
        login_pass = st.text_input("Password:", type="password", key="login_pass")
        login_role = st.selectbox("Role:", ["User", "Admin", "Auditor"], key="login_role")
        
        if st.button("Login", use_container_width=True, key="login_button"):
            authenticated, first_login, user_role = authenticate(login_user, login_pass, login_role)
            
            if authenticated:
                st.session_state["logged_in"] = True
                st.session_state["user"] = login_user
                st.session_state["role"] = user_role
                st.session_state["first_login"] = first_login
                st.rerun() 
            else:
                st.error("Invalid Username, Password, or Role.")

    with tab2:
        st.header("Sign Up ")
        
        signup_user = st.text_input("New Username:", key="signup_user")
        signup_pass = st.text_input("Initial Password:", type="password", key="signup_pass")
        signup_role = st.selectbox("Assign Role:", ["User", "Admin"], key="signup_role")
        
        if st.button("Create Account", use_container_width=True, key="signup_button"):
            if not signup_user or not signup_pass:
                st.warning("Username and Password are required.")
                return

            if save_user(signup_user, signup_pass, signup_role):
                st.success("Account created! Please switch to the Login tab.")
            else:
                st.error("Username already exists.")

def show_password_reset_screen():
    st.title("🔒 First-Time Password Reset")
    user = st.session_state.get("user")
    
    st.info(f"Welcome, **{user}**! Please set a new permanent password.")
    
    new_pass = st.text_input("New Password:", type="password", key="new_pass")
    confirm_pass = st.text_input("Confirm New Password:", type="password", key="confirm_pass")

    if st.button("Set New Password", use_container_width=True):
        if not new_pass or new_pass != confirm_pass:
            st.error("Passwords do not match or fields are empty.")
            return
            
        if update_user_password(user, new_pass):
            st.success("Password updated successfully! You can now access the main menu.")
            st.session_state["first_login"] = False
            st.rerun() 
        else:
            st.error("Failed to update password. Please contact support.")


def show_main_menu():
    st.sidebar.title(f"Welcome, {st.session_state.get('user', 'Guest')}")
    st.sidebar.caption(f"Logged in as: {st.session_state.get('user', 'Guest')}")
    st.sidebar.caption(f"Role: {st.session_state.get('role', 'N/A')}")
    
    if st.sidebar.button("Logout", key="logout_menu"):
        st.session_state.clear()
        st.rerun()
        
    st.title("Document Processing Menu")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("💰 Cash Incentive", use_container_width=True):
            st.session_state["current_process"] = "cash"
            st.rerun()
            
    with col2:
        if st.button("🏦 Bank Document", use_container_width=True):
            st.session_state["current_process"] = "bank"
            st.rerun()
            
    with col3:
        if st.button("📑 EPB", use_container_width=True):
            st.session_state["current_process"] = "epb"
            st.rerun()

def process_screen(config):
    """Generic function to handle all three document processes."""
    
    st.header(config["TITLE"])
    st.caption("Full Drive Scan")
    
    if st.button("⬅ Back to Menu", key="back_button"):
        st.session_state["current_process"] = None
        # Clear process-specific state before returning to menu
        if "found_files_map" in st.session_state: del st.session_state["found_files_map"]
        if "missing_files" in st.session_state: del st.session_state["missing_files"]
        if "merged_output_path" in st.session_state: del st.session_state["merged_output_path"]
        if "order_nos_text" in st.session_state: del st.session_state["order_nos_text"]
        if "common_name_input" in st.session_state: del st.session_state["common_name_input"]
        st.rerun() 
        return

    st.markdown("---")

    # --- Input Section ---
    col_input, col_name = st.columns([1, 1])
    
    # Use default values based on session state. If the key was deleted by "Refresh", it defaults to ""
    default_orders = st.session_state.get("order_nos_text", "")
    default_name = st.session_state.get("common_name_input", "")

    with col_input:
        order_nos_text = st.text_area("Order Numbers (space or newline separated):", height=150, key="order_nos_text", value=default_orders)
        
    with col_name:
        common_name = st.text_input("Common Name (e.g., Supplier Name):", key="common_name_input", value=default_name)
        
    order_nos = order_nos_text.strip().split()
    
    # --- Action Buttons ---
    col_search, col_refresh, col_merge, col_print, col_delete = st.columns(5)
    
    with col_search:
        if st.button("Search", use_container_width=True, type="primary"):
            if not order_nos or not common_name:
                st.error("Order No(s) and Common Name are required!")
            else:
                with st.spinner("⏳ Starting full drive scan. This process is slow and may freeze the browser..."):
                    found_files, missing_files = check_documents_full_scan(
                        order_nos, common_name, config["SUB_FOLDERS"]
                    )
                    st.session_state["found_files_map"] = found_files
                    st.session_state["missing_files"] = missing_files
                    st.session_state["merged_output_path"] = ""
                    
                    st.success("Scan Complete.")
                    st.rerun() 

    with col_refresh:
        # The refresh logic is now reliably handled by the on_click callback
        if st.button("Refresh", use_container_width=True, on_click=refresh_process_fields):
            pass 
            
    with col_merge:
        if st.button("Merge", use_container_width=True, type="secondary"):
            if not st.session_state.get("found_files_map"):
                st.error("Please search for documents first.")
            else:
                merge_documents(
                    st.session_state["found_files_map"], 
                    config, 
                    common_name, 
                    order_nos
                )
                
    with col_print:
        st.button("Print", use_container_width=True, on_click=lambda: st.info("To print the merged document, please open the saved PDF file from the merge folder and use your PDF viewer's print functionality."))
        
    with col_delete:
        if st.button("Delete Merged Files", use_container_width=True):
            merged_path = st.session_state.get("merged_output_path")
            
            if merged_path and os.path.exists(merged_path):
                try:
                    os.remove(merged_path)
                    st.success(f"Deleted merged file: {os.path.basename(merged_path)}")
                    st.session_state["merged_output_path"] = ""
                except Exception as e:
                    st.error(f"Error deleting file: {e}")
            else:
                st.info(f"No merged file found in `{config['MERGE_FOLDER']}` to delete.")
    
    st.markdown("---")
    
    # --- Results Display ---
    found_files_map = st.session_state.get("found_files_map", {})
    missing_files = st.session_state.get("missing_files", {})
    
    if found_files_map or missing_files:
        
        st.subheader("Scan Results")

        if missing_files:
            st.warning("⚠️ Some documents are missing:")
            log = "\n".join([f"- **Order {o[0]}**: Missing {o[1]} ({n})" for o, n in missing_files.items()])
            st.markdown(log)
        else:
            st.success("✅ All required documents found.")

        results = defaultdict(lambda: {"Order No": "", **{f: "❌" for f in config["SUB_FOLDERS"]}})
        for order_no in order_nos:
            results[order_no]["Order No"] = order_no

        for (order_no, folder), _ in found_files_map.items():
            results[order_no][folder] = "✅"
        
        data = [results[order_no] for order_no in order_nos if order_no in results]
        
        st.dataframe(
            data,
            column_order=["Order No"] + config["SUB_FOLDERS"],
            hide_index=True
        )

# --- MAIN APP LOGIC ---

def main():
    st.set_page_config(page_title="Document Manager", layout="wide")
    
    # Initialize ALL session state variables upfront 
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if "first_login" not in st.session_state:
        st.session_state["first_login"] = False
    if "user" not in st.session_state: 
        st.session_state["user"] = None
    if "role" not in st.session_state: 
        st.session_state["role"] = None
    if "found_files_map" not in st.session_state:
        st.session_state["found_files_map"] = {}
    if "merged_output_path" not in st.session_state:
        st.session_state["merged_output_path"] = ""
    if "current_process" not in st.session_state:
        st.session_state["current_process"] = None 

    # Navigation based on session state
    if not st.session_state["logged_in"]:
        show_login_signup_screen()
    elif st.session_state["first_login"]:
        show_password_reset_screen()
    else:
        if st.session_state["current_process"] == "cash":
            process_screen(CASH_CONFIG)
        elif st.session_state["current_process"] == "bank":
            process_screen(BANK_CONFIG)
        elif st.session_state["current_process"] == "epb":
            process_screen(EPB_CONFIG)
        else:
            show_main_menu()

if __name__ == "__main__":
    main()