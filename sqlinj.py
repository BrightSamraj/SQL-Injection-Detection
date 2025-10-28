import streamlit as st
import sqlite3
import random
import logging
import re
import pandas as pd
import os

# --- Logger Setup ---
# Configure logger to write to a file
logging.basicConfig(
    filename='security.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    force=True  # Force re-configuration, useful in Streamlit
)

# --- Database Functions ---

@st.cache_resource
def init_db():
    """Create and populate an in-memory database."""
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    
    # 1. Create the table
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
    for i in range(1, 21):
        username = f'user{i}'
        password = f'pass{random.randint(1000, 9999)}'
        
        if i == 5:
            username = 'user_five'
            password = 'ValidPassword123'
            
        email = f'user{i}@example.com'
        role = random.choice(roles)
        
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            (username, password, email, role)
        )
    
    conn.commit()
    return conn

def get_all_users(conn):
    """Fetches all users from the DB as a DataFrame."""
    try:
        df = pd.read_sql_query("SELECT id, username, password, role FROM users", conn)
        return df
    except Exception as e:
        st.error(f"Error fetching users: {e}")
        return pd.DataFrame()

# --- Security & Login Functions ---

def vulnerable_login(conn, username, password):
    """A DANGEROUSLY vulnerable login function."""
    st.info(f"Attempting login for: '{username}'")
    
    # The vulnerability: building a query with f-string
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    st.code(f"Executing Query: {query}", language="sql")
    
    try:
        cursor = conn.cursor()
        cursor.execute(query) # This line is vulnerable
        user = cursor.fetchone()
        
        if user:
            st.success(f"Login successful! Welcome, {user[1]} (Role: {user[4]})")
            st.balloons()
        else:
            st.error("Login failed: Invalid username or password.")
            
    except Exception as e:
        st.error(f"An SQL error occurred! This often happens during an attack. Error: {e}")
        logging.error(f"VULNERABLE login triggered error: {e}")

def is_valid_input(input_string, field_name):
    """Validates input using a regular expression (RegEx)."""
    if re.fullmatch(r'^[a-zA-Z0-9_]{4,20}$', input_string):
        return True
    else:
        st.warning(f"Validation FAILED for {field_name}: Input has invalid characters or length.")
        logging.warning(f"Validation failed for {field_name}. Input: {input_string}")
        return False

def secure_login(conn, username, password):
    """A SECURE login function using validation and parameterized queries."""
    st.info(f"Attempting login for: '{username}'")
    
    # 1. VALIDATION
    if not is_valid_input(username, "username") or not is_valid_input(password, "password"):
        st.error("Login failed: Invalid input format.")
        return

    # 2. PARAMETERIZED QUERY
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    st.code(f"Executing Query: {query}\nWith Parameters: ({username}, {password})", language="sql")
    
    try:
        cursor = conn.cursor()
        # Pass variables as a separate tuple to prevent injection
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        
        if user:
            st.success(f"Login successful! Welcome, {user[1]} (Role: {user[4]})")
        else:
            st.error("Login failed: Invalid username or password.")
            
    except sqlite3.Error as e:
        st.error(f"A database error occurred: {e}")
        logging.error(f"SECURE login triggered error: {e}")

# --- Main Streamlit App UI ---

st.set_page_config(page_title="SQL Injection Demo", layout="wide")
st.title("🛡️ SQL Injection: Attack & Defense Demo")
st.write("""
This app demonstrates how SQL Injection attacks work and how to prevent them. 
The database is in-memory and resets every time you refresh the page.
A test user exists: **Username:** `user_five`, **Password:** `ValidPassword123`
""")

# Initialize the database connection
conn = init_db()

# Create tabs for different sections
tab1, tab2, tab3 = st.tabs(["💥 Attack (Vulnerable Login)", "🛡️ Defense (Secure Login)", "🔎 View Database & Log"])

# --- Tab 1: Vulnerable Attack Demo ---
with tab1:
    st.header("💥 The Vulnerable Login")
    st.warning("This login form is **intentionally insecure**. It uses string formatting to build the query.")
    
    with st.form("vulnerable_form"):
        v_username = st.text_input("Username", value="user_five")
        v_password = st.text_input("Password", value="' OR '1'='1")
        v_submitted = st.form_submit_button("Login")
        
    if v_submitted:
        vulnerable_login(conn, v_username, v_password)
    
    st.subheader("Try These Payloads:")
    st.code("' OR '1'='1", language="sql")
    st.write("Bypasses the password check and logs you in as the *first user* in the database.")
    st.code("'; DROP TABLE users; --", language="sql")
    st.write("Attempts to delete the entire 'users' table. (May fail depending on DB config, but shows the danger).")

# --- Tab 2: Secure Defense Demo ---
with tab2:
    st.header("🛡️ The Secure Login")
    st.success("This form is **secure**. It uses **Input Validation** and **Parameterized Queries**.")
    
    with st.form("secure_form"):
        s_username = st.text_input("Username", value="user_five")
        s_password = st.text_input("Password", value="' OR '1'='1")
        s_submitted = st.form_submit_button("Login")
        
    if s_submitted:
        secure_login(conn, s_username, s_password)

    st.subheader("How It Works:")
    st.markdown("""
    1.  **Input Validation:** The code first checks if the input `matches` a safe pattern (e.g., only letters/numbers). The payload `' OR '1'='1` fails this check because it contains `'` and spaces.
    2.  **Parameterized Queries:** Even if validation fails, the query itself is safe. The database is told: "Find a user whose name is `user_five` and whose password is the literal string `' OR '1'='1`". No such user exists, so the login correctly fails.
    """)
    st.subheader("Try a valid login:")
    st.code("Username: user_five\nPassword: ValidPassword123", language="text")

# --- Tab 3: View Database & Log ---
with tab3:
    st.header("🔎 Database and Log Viewer")
    st.write("See what's happening behind the scenes.")
    
    # Database Viewer
    st.subheader("Current 'users' Table")
    if st.button("Refresh Database View"):
        pass  # Just forces a rerun to refresh
    
    db_data = get_all_users(conn)
    st.dataframe(db_data)
    
    # Log Viewer
    st.subheader("Security Log (`security.log`)")
    if st.button("Refresh Log View"):
        pass # Just forces a rerun to refresh

    log_file = 'security.log'
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            log_contents = f.read()
            if log_contents:
                st.code(log_contents, language="log")
            else:
                st.info("Log file is currently empty.")
    else:
        st.info("Log file has not been created yet. (Try a failed validation in the 'Secure Login' tab).")
