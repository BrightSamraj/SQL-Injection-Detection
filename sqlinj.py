import streamlit as st
import sqlite3
import random
import re
import logging
import os
import pandas as pd

# --- Configuration ---
LOG_FILE = 'security.log'

# --- 1. Logger Setup ---
# Clear the log file for a clean demo each time the app reruns
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)

# Set up a logger to write suspicious activity to a file
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- 2. Database Setup ---
@st.cache_resource
def setup_database():
    """
    Creates an in-memory database, a 5-column table,
    and populates it with 20 rows.
    
    We use @st.cache_resource to ensure the database
    persists across Streamlit reruns.
    """
    st.toast("Creating new in-memory database...")
    # Use :memory: to create a database that exists only in RAM
    # check_same_thread=False is needed for Streamlit's threading
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    
    # 1. Create the table with 5 columns
    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'user'
    )
    ''')

    # 2. Insert 20 rows of dummy data
    roles = ['user', 'admin', 'guest']
    known_user = 'test_user'
    known_pass = 'ValidPassword123'
    
    for i in range(1, 21):
        if i == 5:
            username = known_user
            password = known_pass
            role = 'admin'
        else:
            username = f'user{i}'
            password = f'pass{random.randint(1000, 9999)}'
            role = random.choice(roles)
        
        email = f'{username}@example.com'
        
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            (username, password, email, role)
        )

    conn.commit()
    return conn, known_user, known_pass

def get_all_users(conn):
    """Helper function to fetch all users as a Pandas DataFrame."""
    return pd.read_sql_query("SELECT id, username, password, role FROM users", conn)

# --- 3. The "Scanner" (Detection Feature) ---
def is_valid_input(input_string, field_name):
    """
    This is our "Python Scanner" (Input Validation).
    It checks if the input matches a safe pattern (alphanumeric + underscore).
    """
    # This RegEx pattern only allows letters, numbers, and underscores,
    # and a length between 4 and 20 characters.
    if re.fullmatch(r'^[a-zA-Z0-9_]{4,20}$', input_string):
        return True
    else:
        # DETECTED: The input is suspicious. Log it.
        st.warning(f"DETECTION: Input for '{field_name}' failed validation!")
        logging.warning(f"Validation failed for {field_name}. Malicious input suspected: {input_string}")
        return False

# --- 4. Login Logic (Vulnerable vs. Secure) ---

def vulnerable_login(conn, username, password):
    """
    A DANGEROUSLY vulnerable login function.
    It builds a query by pasting user input directly.
    """
    st.info(f"Attempting VULNERABLE login...")
    
    # THE VULNERABILITY: Using f-string to build the query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    st.code(f"Executing DANGEROUS query:\n{query}", language="sql")
    
    try:
        cursor = conn.cursor()
        cursor.execute(query) # The flaw is here
        user = cursor.fetchone()
        
        if user:
            st.success(f"!!! VULNERABLE SUCCESS (HACKED) !!!")
            st.success(f"Logged in as: {user[1]} (Role: {user[4]})")
            st.balloons()
        else:
            st.error("--- VULNERABLE FAILED --- Login incorrect.")
    except Exception as e:
        st.error(f"Query failed! This often happens with attacks like 'DROP TABLE'. Error: {e}")

def secure_login(conn, username, password):
    """
    A SECURE login function.
    It uses 1. Validation (Detection) and 2. Parameterized Queries (Prevention).
    """
    st.info(f"Attempting SECURE login...")
    
    # 1. VALIDATION (Detection Feature)
    if not is_valid_input(username, "username") or not is_valid_input(password, "password"):
        st.error("--- SECURE FAILED --- Invalid input format. Login rejected.")
        return

    # 2. PARAMETERIZED QUERY (Prevention Feature)
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    st.code(f"Executing SECURE query:\n{query}", language="sql")
    st.code(f"With parameters: ('{username}', '{password}')")
    
    try:
        cursor = conn.cursor()
        # The fix is here: Pass the data as a separate tuple.
        # The database engine safely handles the data, preventing execution.
        cursor.execute(query, (username, password)) 
        user = cursor.fetchone()
        
        if user:
            st.success(f"--- SECURE SUCCESS --- Login successful.")
            st.success(f"Logged in as: {user[1]} (Role: {user[4]})")
        else:
            st.error("--- SECURE FAILED --- Login incorrect (user/pass not found).")
    except sqlite3.Error as e:
        st.error(f"A database error occurred: {e}")

# --- 5. Streamlit App UI ---
st.set_page_config(page_title="SQL Injection Demo", layout="wide", initial_sidebar_state="collapsed")
st.title("🛡️ SQL Injection: Attack vs. Defense Demo")
st.write("This app demonstrates how SQL Injection attacks work and how to prevent them using a live in-memory database.")

# Setup DB and get test credentials
conn, test_user, test_pass = setup_database()

st.info(f"Database is ready. A test user exists: **Username:** `{test_user}` | **Password:** `{test_pass}`")

# Define the attack payload
attack_payload = "' OR '1'='1"

# Create tabs for the demo
tab_attack, tab_defense, tab_db, tab_log = st.tabs([
    "💥 1. The VULNERABLE Attack", 
    "🛡️ 2. The SECURE Defense", 
    "🏦 3. View The Database", 
    "🔎 4. View The 'Scanner' Log"
])

# --- Tab 1: Attack ---
with tab_attack:
    st.header("💥 The Attack Scenario")
    st.warning("This login form is **intentionally vulnerable**. It builds the SQL query using f-strings, which is dangerous!")
    
    st.subheader("Try the Attack")
    st.write(f"We will use the following payload for the password: `{attack_payload}`")
    st.write("This payload is designed to make the `WHERE` clause always true, bypassing the password check.")
    
    with st.form("vulnerable_form"):
        v_username = st.text_input("Username", value=test_user)
        v_password = st.text_input("Password", value=attack_payload)
        v_submitted = st.form_submit_button("Attempt HACKED Login")
        
    if v_submitted:
        vulnerable_login(conn, v_username, v_password)

# --- Tab 2: Defense ---
with tab_defense:
    st.header("🛡️ The Defense Scenario")
    st.success("This form is **SECURE**. It uses two key techniques:")
    st.markdown("""
        1.  **Input Validation (Our "Scanner"):** Rejects input with suspicious characters.
        2.  **Parameterized Queries (The "Cure"):** Treats all input as data, never as executable code.
    """)
    
    st.subheader("Attempt 1: Try the SAME Attack")
    st.write(f"We will use the same malicious payload: `{attack_payload}`")

    with st.form("secure_form_attack"):
        s_username_att = st.text_input("Username", value=test_user, key="s_user_1")
        s_password_att = st.text_input("Password", value=attack_payload, key="s_pass_1")
        s_submitted_att = st.form_submit_button("Attempt SECURE Login (with attack)")
        
    if s_submitted_att:
        secure_login(conn, s_username_att, s_password_att)

    st.divider()
    
    st.subheader("Attempt 2: Try a Valid Login")
    st.write("Now, we'll use the correct, valid credentials.")
    
    with st.form("secure_form_valid"):
        s_username_val = st.text_input("Username", value=test_user, key="s_user_2")
        s_password_val = st.text_input("Password", value=test_pass, key="s_pass_2", type="password")
        s_submitted_val = st.form_submit_button("Attempt SECURE Login (with valid pass)")
        
    if s_submitted_val:
        secure_login(conn, s_username_val, s_password_val)

# --- Tab 3: Database Viewer ---
with tab_db:
    st.header("🏦 Live Database View")
    st.write("This is the current data in the `users` table.")
    if st.button("Refresh Database"):
        st.toast("Database view refreshed!")
    st.dataframe(get_all_users(conn), use_container_width=True)

# --- Tab 4: Log Viewer ---
with tab_log:
    st.header("🔎 Live 'Scanner' Log (`security.log`)")
    st.write("Our 'scanner' (the validation function) logs all suspicious attempts here.")
    
    if st.button("Refresh Log"):
        st.toast("Log view refreshed!")
        
    try:
        with open(LOG_FILE, 'r') as f:
            log_contents = f.read()
            if log_contents:
                st.code(log_contents, language="log")
            else:
                st.info("Log file is currently empty. Try a 'secure' login with the attack payload to see a log entry.")
    except FileNotFoundError:
        st.info("Log file has not been created yet.")
