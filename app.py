import streamlit as st
import sqlite3
import os
from hashlib import sha256
from datetime import datetime

# Initialize database
def init_db():
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, is_admin BOOLEAN)''')
    
    # Create files table
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT,
                  uploaded_by TEXT,
                  upload_date TEXT,
                  file_path TEXT)''')
    
    # Add admin user if not exists
    admin_password = sha256("admin@321".encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", 
             ("admin", admin_password, True))
    
    conn.commit()
    conn.close()

# Initialize the upload directory
def init_upload_dir():
    if not os.path.exists("uploads"):
        os.makedirs("uploads")

# Hash password
def hash_password(password):
    return sha256(password.encode()).hexdigest()

# Verify login
def verify_login(username, password):
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()
    hashed_password = hash_password(password)
    c.execute("SELECT * FROM users WHERE username=? AND password=?", 
             (username, hashed_password))
    user = c.fetchone()
    conn.close()
    return user

# Check if user is admin
def is_admin(username):
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else False

# Add new user
def add_user(username, password, is_admin=False):
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()
    hashed_password = hash_password(password)
    try:
        c.execute("INSERT INTO users VALUES (?, ?, ?)", 
                 (username, hashed_password, is_admin))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

# Remove user
def remove_user(username):
    if username == "admin":
        return False
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=? AND username != 'admin'", 
             (username,))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    return success

# Save uploaded file
def save_file(uploaded_file, username):
    if uploaded_file is not None:
        file_path = os.path.join("uploads", uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        conn = sqlite3.connect('cloud_storage.db')
        c = conn.cursor()
        c.execute("""INSERT INTO files (filename, uploaded_by, upload_date, file_path)
                    VALUES (?, ?, ?, ?)""", 
                 (uploaded_file.name, username, 
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S"), file_path))
        conn.commit()
        conn.close()
        return True
    return False

# Get user's files
def get_user_files(username):
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()
    c.execute("""SELECT filename, upload_date, file_path 
                 FROM files WHERE uploaded_by=?""", (username,))
    files = c.fetchall()
    conn.close()
    return files

# Main application
def main():
    st.set_page_config(page_title="Cloud Storage App", layout="wide")
    init_db()
    init_upload_dir()
    
    # Session state initialization
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    
    # Login page
    if not st.session_state.logged_in:
        st.title("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            user = verify_login(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success("Login successful!")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")
    
    # Main application pages
    else:
        st.sidebar.title("Navigation")
        page = st.sidebar.radio("Go to", ["Home", "Admin"] if is_admin(st.session_state.username) else ["Home"])
        
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.experimental_rerun()
        
        if page == "Home":
            st.title("Cloud Storage")
            st.write(f"Welcome, {st.session_state.username}!")
            
            # File upload
            uploaded_file = st.file_uploader("Choose a file")
            if uploaded_file is not None:
                if st.button("Upload"):
                    if save_file(uploaded_file, st.session_state.username):
                        st.success("File uploaded successfully!")
                    else:
                        st.error("Error uploading file")
            
            # Display user's files
            st.subheader("Your Files")
            files = get_user_files(st.session_state.username)
            if files:
                for file in files:
                    col1, col2, col3 = st.columns([2, 2, 1])
                    with col1:
                        st.write(f"📄 {file[0]}")
                    with col2:
                        st.write(file[1])  # Upload date
                    with col3:
                        with open(file[2], "rb") as f:
                            st.download_button(
                                label="Download",
                                data=f,
                                file_name=file[0],
                                key=file[1]
                            )
            else:
                st.info("No files uploaded yet")
        
        elif page == "Admin":
            st.title("Admin Panel")
            
            # Add new user
            st.subheader("Add New User")
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            is_admin_user = st.checkbox("Is Admin")
            
            if st.button("Add User"):
                if add_user(new_username, new_password, is_admin_user):
                    st.success("User added successfully!")
                else:
                    st.error("Username already exists")
            
            # Remove user
            st.subheader("Remove User")
            conn = sqlite3.connect('cloud_storage.db')
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE username != 'admin'")
            users = [user[0] for user in c.fetchall()]
            conn.close()
            
            if users:
                user_to_remove = st.selectbox("Select user to remove", users)
                if st.button("Remove User"):
                    if remove_user(user_to_remove):
                        st.success(f"User {user_to_remove} removed successfully!")
                    else:
                        st.error("Error removing user")
            else:
                st.info("No users to remove")

if __name__ == "__main__":
    main()