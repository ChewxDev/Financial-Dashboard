import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, date
import sqlite3
import hashlib
import os
import re
from typing import Optional, Tuple, List
import uuid
from urllib.parse import urlencode

# Page configuration
st.set_page_config(
    page_title="Personal Finance Tracker",
    page_icon="💰",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Security and validation functions
def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_username(username: str) -> bool:
    """Validate username format"""
    if len(username) < 3 or len(username) > 30:
        return False
    pattern = r'^[a-zA-Z0-9_.-]+$'
    return bool(re.match(pattern, username))

def validate_password(password: str) -> bool:
    """Validate password strength"""
    if len(password) < 6:
        return False
    return True

def hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt"""
    salt = os.urandom(32)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + pwdhash.hex()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        salt = bytes.fromhex(hashed[:64])
        stored_hash = bytes.fromhex(hashed[64:])
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return pwdhash == stored_hash
    except (ValueError, IndexError):
        return False

def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not text:
        return ""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\';\\]', '', str(text))
    return sanitized.strip()

# Database configuration
DATABASE_FILE = 'finance_tracker.db'

@st.cache_resource
def init_database():
    """Initialize SQLite database with proper error handling"""
    try:
        conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
        conn.execute('PRAGMA foreign_keys = ON')
        
        # Create users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create income table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS income (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date DATE NOT NULL,
                amount REAL NOT NULL CHECK(amount > 0),
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Create expenses table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date DATE NOT NULL,
                amount REAL NOT NULL CHECK(amount > 0),
                category TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Create user sessions table for persistent login
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        st.error(f"Database initialization failed: {e}")
        return False

def get_db_connection():
    """Get database connection with proper error handling"""
    try:
        conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
        conn.execute('PRAGMA foreign_keys = ON')
        return conn
    except sqlite3.Error as e:
        st.error(f"Database connection failed: {e}")
        return None

# Expense categories
EXPENSE_CATEGORIES = [
    'Food & Dining',
    'Transportation',
    'Shopping',
    'Entertainment',
    'Bills & Utilities',
    'Healthcare',
    'Travel',
    'Education',
    'Investment',
    'Other'
]

# User management functions
def create_session_token(user_id: int) -> str:
    """Create a secure session token for persistent login"""
    token = str(uuid.uuid4())
    conn = get_db_connection()
    if not conn:
        return ""
    
    try:
        # Clean old tokens (older than 30 days)
        conn.execute("DELETE FROM user_sessions WHERE created_at < datetime('now', '-30 days')")
        
        # Insert new token
        conn.execute(
            "INSERT INTO user_sessions (user_id, token, created_at) VALUES (?, ?, datetime('now'))",
            (user_id, token)
        )
        conn.commit()
        return token
    except sqlite3.Error:
        return ""
    finally:
        conn.close()

def verify_session_token(token: str) -> Optional[int]:
    """Verify session token and return user_id"""
    if not token:
        return None
    
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.execute(
            "SELECT user_id FROM user_sessions WHERE token = ? AND created_at > datetime('now', '-30 days')",
            (token,)
        )
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.Error:
        return None
    finally:
        conn.close()

def get_username_by_id(user_id: int) -> str:
    """Get username by user ID"""
    conn = get_db_connection()
    if not conn:
        return ""
    
    try:
        cursor = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        return result[0] if result else ""
    except sqlite3.Error:
        return ""
    finally:
        conn.close()

def create_user(username: str, email: str, password: str) -> Optional[int]:
    """Create a new user with proper validation"""
    # Input validation
    if not validate_username(username):
        st.error("Username must be 3-30 characters long and contain only letters, numbers, dots, dashes, and underscores")
        return None
    
    if not validate_email(email):
        st.error("Please enter a valid email address")
        return None
    
    if not validate_password(password):
        st.error("Password must be at least 6 characters long")
        return None
    
    # Sanitize inputs
    username = sanitize_input(username)
    email = sanitize_input(email)
    
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        hashed_password = hash_password(password)
        cursor = conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )
        user_id = cursor.lastrowid
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        st.error("Username or email already exists")
        return None
    except sqlite3.Error as e:
        st.error(f"Error creating user: {e}")
        return None
    finally:
        conn.close()

def verify_user(username: str, password: str) -> Optional[int]:
    """Verify user credentials"""
    if not username or not password:
        return None
    
    username = sanitize_input(username)
    
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result and verify_password(password, result[1]):
            return result[0]
        return None
    except sqlite3.Error as e:
        st.error(f"Login error: {e}")
        return None
    finally:
        conn.close()

def get_user_data(user_id: int, table_name: str) -> pd.DataFrame:
    """Get user's financial data from database"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        if table_name == 'income':
            query = "SELECT date, amount, description FROM income WHERE user_id = ? ORDER BY date DESC"
            columns = ['Date', 'Amount', 'Description']
        else:  # expenses
            query = "SELECT date, amount, category, description FROM expenses WHERE user_id = ? ORDER BY date DESC"
            columns = ['Date', 'Amount', 'Category', 'Description']
        
        df = pd.read_sql_query(query, conn, params=[user_id])
        if df.empty:
            return pd.DataFrame(columns=columns)
        
        # Ensure proper column names
        df.columns = columns
        return df
        
    except sqlite3.Error as e:
        st.error(f"Error fetching data: {e}")
        return pd.DataFrame(columns=columns)
    finally:
        conn.close()

def add_income_entry(user_id: int, date_input: date, amount: float, description: str) -> bool:
    """Add a new income entry to the database"""
    if amount <= 0:
        st.error("Amount must be greater than 0")
        return False
    
    description = sanitize_input(description)
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        conn.execute(
            "INSERT INTO income (user_id, date, amount, description) VALUES (?, ?, ?, ?)",
            (user_id, date_input.isoformat(), float(amount), description)
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        st.error(f"Error adding income: {e}")
        return False
    finally:
        conn.close()

def add_expense_entry(user_id: int, date_input: date, amount: float, category: str, description: str) -> bool:
    """Add a new expense entry to the database"""
    if amount <= 0:
        st.error("Amount must be greater than 0")
        return False
    
    if category not in EXPENSE_CATEGORIES:
        st.error("Invalid expense category")
        return False
    
    description = sanitize_input(description)
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        conn.execute(
            "INSERT INTO expenses (user_id, date, amount, category, description) VALUES (?, ?, ?, ?, ?)",
            (user_id, date_input.isoformat(), float(amount), category, description)
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        st.error(f"Error adding expense: {e}")
        return False
    finally:
        conn.close()

def clear_user_data(user_id: int, data_type: str) -> bool:
    """Clear user's income or expense data"""
    if data_type not in ['income', 'expenses']:
        return False
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        if data_type == 'income':
            conn.execute("DELETE FROM income WHERE user_id = ?", (user_id,))
        else:  # expenses
            conn.execute("DELETE FROM expenses WHERE user_id = ?", (user_id,))
        
        conn.commit()
        return True
    except sqlite3.Error as e:
        st.error(f"Error clearing data: {e}")
        return False
    finally:
        conn.close()

def calculate_financial_metrics(income_data: pd.DataFrame, expense_data: pd.DataFrame) -> Tuple[float, float, float, float]:
    """Calculate key financial metrics"""
    total_income = float(income_data['Amount'].sum()) if not income_data.empty else 0.0
    total_expenses = float(expense_data['Amount'].sum()) if not expense_data.empty else 0.0
    net_savings = total_income - total_expenses
    savings_rate = (net_savings / total_income * 100) if total_income > 0 else 0.0
    
    return total_income, total_expenses, net_savings, savings_rate

def create_spending_over_time_chart(expense_data: pd.DataFrame):
    """Create a chart showing spending patterns over time"""
    if expense_data.empty:
        return None
    
    try:
        # Convert Date column to datetime
        expense_df = expense_data.copy()
        expense_df['Date'] = pd.to_datetime(expense_df['Date'])
        
        # Group by date and sum amounts
        daily_expenses = expense_df.groupby('Date')['Amount'].sum().reset_index()
        
        fig = px.line(daily_expenses, x='Date', y='Amount', 
                      title='Daily Spending Over Time',
                      labels={'Amount': 'Amount ($)', 'Date': 'Date'})
        fig.update_traces(line_color='#ff6b6b')
        
        return fig
    except Exception as e:
        st.error(f"Error creating spending chart: {e}")
        return None

def create_category_breakdown_chart(expense_data: pd.DataFrame):
    """Create a pie chart showing expense breakdown by category"""
    if expense_data.empty:
        return None
    
    try:
        category_totals = expense_data.groupby('Category')['Amount'].sum()
        
        fig = px.pie(values=category_totals.values, names=category_totals.index,
                     title='Expense Breakdown by Category')
        
        return fig
    except Exception as e:
        st.error(f"Error creating category chart: {e}")
        return None

def create_monthly_breakdown_chart(income_data: pd.DataFrame, expense_data: pd.DataFrame):
    """Create a bar chart showing monthly income vs expenses"""
    if income_data.empty and expense_data.empty:
        return None
    
    try:
        monthly_income = pd.Series(dtype=float)
        monthly_expenses = pd.Series(dtype=float)
        
        # Process income data
        if not income_data.empty:
            income_df = income_data.copy()
            income_df['Date'] = pd.to_datetime(income_df['Date'])
            income_df['Month'] = income_df['Date'].dt.to_period('M').astype(str)
            monthly_income = income_df.groupby('Month')['Amount'].sum()
        
        # Process expense data
        if not expense_data.empty:
            expense_df = expense_data.copy()
            expense_df['Date'] = pd.to_datetime(expense_df['Date'])
            expense_df['Month'] = expense_df['Date'].dt.to_period('M').astype(str)
            monthly_expenses = expense_df.groupby('Month')['Amount'].sum()
        
        # Combine data
        all_months = sorted(set(monthly_income.index.tolist() + monthly_expenses.index.tolist()))
        
        if not all_months:
            return None
        
        income_values = [monthly_income.get(month, 0) for month in all_months]
        expense_values = [monthly_expenses.get(month, 0) for month in all_months]
        
        fig = go.Figure()
        fig.add_trace(go.Bar(name='Income', x=all_months, y=income_values, marker_color='#4ecdc4'))
        fig.add_trace(go.Bar(name='Expenses', x=all_months, y=expense_values, marker_color='#ff6b6b'))
        
        fig.update_layout(
            title='Monthly Income vs Expenses',
            xaxis_title='Month',
            yaxis_title='Amount ($)',
            barmode='group'
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating monthly chart: {e}")
        return None

# Authentication UI
def show_login_signup():
    """Show login and signup forms"""
    st.markdown("### Welcome to Personal Finance Tracker")
    st.markdown("Manage your income and expenses with detailed analytics and insights.")
    
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        st.subheader("Login to Your Account")
        
        # Add custom HTML for autofill support
        st.markdown(
            """
            <style>
            .stTextInput input {
                autocomplete: on !important;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        
        login_username = st.text_input(
            "Username", 
            key="login_username", 
            max_chars=30,
            help="Your username",
            placeholder="Enter your username"
        )
        
        login_password = st.text_input(
            "Password", 
            type="password", 
            key="login_password", 
            max_chars=100,
            help="Your password",
            placeholder="Enter your password"
        )
        
        remember_me = st.checkbox("Stay logged in", help="Keep you logged in across browser sessions")
        
        if st.button("Login", type="primary"):
            if login_username.strip() and login_password:
                with st.spinner("Authenticating..."):
                    user_id = verify_user(login_username.strip(), login_password)
                    if user_id:
                        st.session_state['authenticated'] = True
                        st.session_state['user_id'] = user_id
                        st.session_state['username'] = login_username.strip()
                        
                        # Create persistent session if "Stay logged in" is checked
                        if remember_me:
                            token = create_session_token(user_id)
                            if token:
                                # Store token in query params for persistence
                                st.query_params["session_token"] = token
                        
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
            else:
                st.error("Please enter both username and password")
    
    with tab2:
        st.subheader("Create New Account")
        
        # Add custom HTML for autofill support
        st.markdown(
            """
            <style>
            .stTextInput input[type="text"] {
                autocomplete: username !important;
            }
            .stTextInput input[type="email"] {
                autocomplete: email !important;
            }
            .stTextInput input[type="password"]:first-of-type {
                autocomplete: new-password !important;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        
        signup_username = st.text_input(
            "Username", 
            key="signup_username", 
            max_chars=30,
            help="3-30 characters, letters, numbers, dots, dashes, underscores only",
            placeholder="Choose a username"
        )
        
        signup_email = st.text_input(
            "Email", 
            key="signup_email", 
            max_chars=100,
            placeholder="your.email@example.com"
        )
        
        signup_password = st.text_input(
            "Password", 
            type="password", 
            key="signup_password", 
            max_chars=100,
            help="Minimum 6 characters",
            placeholder="Create a secure password"
        )
        
        signup_password_confirm = st.text_input(
            "Confirm Password", 
            type="password", 
            key="signup_password_confirm", 
            max_chars=100,
            placeholder="Confirm your password"
        )
        
        if st.button("Sign Up", type="primary"):
            if all([signup_username.strip(), signup_email.strip(), signup_password, signup_password_confirm]):
                if signup_password == signup_password_confirm:
                    with st.spinner("Creating account..."):
                        user_id = create_user(signup_username.strip(), signup_email.strip(), signup_password)
                        if user_id:
                            st.success("Account created successfully! Please login with your new credentials.")
                else:
                    st.error("Passwords do not match")
            else:
                st.error("Please fill in all fields")

# Main application
def main_dashboard():
    """Main dashboard after authentication"""
    # Get user data from database
    income_data = get_user_data(st.session_state['user_id'], 'income')
    expense_data = get_user_data(st.session_state['user_id'], 'expenses')
    
    # Header with logout button
    col1, col2 = st.columns([4, 1])
    with col1:
        st.title(f"💰 Personal Finance Tracker")
        st.markdown(f"**Welcome back, {st.session_state['username']}!** Track your financial progress with detailed insights.")
    with col2:
        if st.button("Logout", type="secondary"):
            # Clear session token from query params
            if "session_token" in st.query_params:
                del st.query_params["session_token"]
            
            # Clear all session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Sidebar for data input
    with st.sidebar:
        st.header("📝 Add New Entry")
        
        entry_type = st.selectbox("Entry Type", ["Income", "Expense"])
        
        if entry_type == "Income":
            st.subheader("💵 Add Income")
            income_date = st.date_input("Date", value=date.today(), key="income_date", max_value=date.today())
            income_amount = st.number_input("Amount ($)", min_value=0.01, max_value=1000000.00, step=0.01, key="income_amount")
            income_description = st.text_input("Description", placeholder="Salary, freelance, etc.", key="income_desc", max_chars=200)
            
            if st.button("Add Income", type="primary"):
                if add_income_entry(st.session_state['user_id'], income_date, income_amount, income_description):
                    st.success("Income entry added successfully!")
                    st.rerun()
        
        else:
            st.subheader("💸 Add Expense")
            expense_date = st.date_input("Date", value=date.today(), key="expense_date", max_value=date.today())
            expense_amount = st.number_input("Amount ($)", min_value=0.01, max_value=1000000.00, step=0.01, key="expense_amount")
            expense_category = st.selectbox("Category", EXPENSE_CATEGORIES, key="expense_category")
            expense_description = st.text_input("Description", placeholder="Restaurant, gas, etc.", key="expense_desc", max_chars=200)
            
            if st.button("Add Expense", type="primary"):
                if add_expense_entry(st.session_state['user_id'], expense_date, expense_amount, expense_category, expense_description):
                    st.success("Expense entry added successfully!")
                    st.rerun()
        
        st.markdown("---")
        
        # Data management options
        st.subheader("🗑️ Data Management")
        
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("Clear Income", type="secondary", help="Delete all income data"):
                if st.session_state.get('confirm_clear_income'):
                    if clear_user_data(st.session_state['user_id'], 'income'):
                        st.success("Income data cleared!")
                        st.session_state['confirm_clear_income'] = False
                        st.rerun()
                else:
                    st.session_state['confirm_clear_income'] = True
                    st.warning("Click again to confirm deletion")
        
        with col_b:
            if st.button("Clear Expenses", type="secondary", help="Delete all expense data"):
                if st.session_state.get('confirm_clear_expenses'):
                    if clear_user_data(st.session_state['user_id'], 'expenses'):
                        st.success("Expense data cleared!")
                        st.session_state['confirm_clear_expenses'] = False
                        st.rerun()
                else:
                    st.session_state['confirm_clear_expenses'] = True
                    st.warning("Click again to confirm deletion")

    # Main dashboard content
    col1, col2, col3, col4 = st.columns(4)

    # Calculate and display financial metrics
    total_income, total_expenses, net_savings, savings_rate = calculate_financial_metrics(income_data, expense_data)

    with col1:
        st.metric(
            label="💰 Total Income",
            value=f"${total_income:,.2f}",
            delta=None
        )

    with col2:
        st.metric(
            label="💸 Total Expenses",
            value=f"${total_expenses:,.2f}",
            delta=None
        )

    with col3:
        st.metric(
            label="💵 Net Savings",
            value=f"${net_savings:,.2f}",
            delta=None,
            delta_color="normal" if net_savings >= 0 else "inverse"
        )

    with col4:
        st.metric(
            label="📊 Savings Rate",
            value=f"{savings_rate:.1f}%",
            delta=None,
            delta_color="normal" if savings_rate >= 0 else "inverse"
        )

    # Charts section
    st.markdown("---")

    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["📈 Spending Trends", "🥧 Category Analysis", "📅 Monthly Overview", "📋 Recent Entries"])

    with tab1:
        spending_chart = create_spending_over_time_chart(expense_data)
        if spending_chart:
            st.plotly_chart(spending_chart, use_container_width=True)
        else:
            st.info("📊 No expense data available. Add some expenses to see spending patterns over time.")

    with tab2:
        category_chart = create_category_breakdown_chart(expense_data)
        if category_chart:
            st.plotly_chart(category_chart, use_container_width=True)
        else:
            st.info("🥧 No expense data available. Add some expenses to see category breakdown.")

    with tab3:
        monthly_chart = create_monthly_breakdown_chart(income_data, expense_data)
        if monthly_chart:
            st.plotly_chart(monthly_chart, use_container_width=True)
        else:
            st.info("📅 No financial data available. Add income and expense entries to see monthly overview.")

    with tab4:
        col_left, col_right = st.columns(2)
        
        with col_left:
            st.subheader("💰 Recent Income")
            if not income_data.empty:
                # Display last 10 entries
                recent_income = income_data.head(10).copy()
                recent_income['Amount'] = recent_income['Amount'].apply(lambda x: f"${x:,.2f}")
                st.dataframe(recent_income, hide_index=True, use_container_width=True)
            else:
                st.info("No income entries yet.")
        
        with col_right:
            st.subheader("💸 Recent Expenses")
            if not expense_data.empty:
                # Display last 10 entries
                recent_expenses = expense_data.head(10).copy()
                recent_expenses['Amount'] = recent_expenses['Amount'].apply(lambda x: f"${x:,.2f}")
                st.dataframe(recent_expenses, hide_index=True, use_container_width=True)
            else:
                st.info("No expense entries yet.")

    # Financial insights section
    if total_income > 0 or total_expenses > 0:
        st.markdown("---")
        st.subheader("📊 Financial Insights")
        
        insight_col1, insight_col2 = st.columns(2)
        
        with insight_col1:
            if savings_rate >= 20:
                st.success("🎉 Excellent! You're saving 20% or more of your income.")
            elif savings_rate >= 10:
                st.info("👍 Good job! You're saving over 10% of your income.")
            elif savings_rate > 0:
                st.warning("⚠️ You're saving money, but consider increasing your savings rate to at least 10%.")
            else:
                st.error("🚨 You're spending more than you earn. Consider reviewing your expenses.")
        
        with insight_col2:
            if not expense_data.empty:
                top_category = expense_data.groupby('Category')['Amount'].sum().idxmax()
                top_category_amount = expense_data.groupby('Category')['Amount'].sum().max()
                st.info(f"💸 Top spending category: **{top_category}** (${top_category_amount:,.2f})")

    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666; padding: 20px;'>
            <p>Personal Finance Tracker | Secure • Private • Easy to Use</p>
            <small>Your financial data is stored locally and securely.</small>
        </div>
        """,
        unsafe_allow_html=True
    )

# Initialize session state
def check_persistent_login():
    """Check for persistent login via session token"""
    if not st.session_state.get('authenticated', False):
        # Check for session token in query params
        session_token = st.query_params.get("session_token")
        if session_token:
            user_id = verify_session_token(session_token)
            if user_id:
                username = get_username_by_id(user_id)
                if username:
                    st.session_state['authenticated'] = True
                    st.session_state['user_id'] = user_id
                    st.session_state['username'] = username
                    return True
            else:
                # Invalid token, remove it
                if "session_token" in st.query_params:
                    del st.query_params["session_token"]
    return st.session_state.get('authenticated', False)

def init_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
    
    if 'confirm_clear_income' not in st.session_state:
        st.session_state['confirm_clear_income'] = False
    
    if 'confirm_clear_expenses' not in st.session_state:
        st.session_state['confirm_clear_expenses'] = False

# Main app logic
def main():
    """Main application entry point"""
    # Initialize database
    if not init_database():
        st.error("Failed to initialize database. Please check file permissions and try again.")
        st.stop()
    
    # Initialize session state
    init_session_state()
    
    # Check for persistent login
    check_persistent_login()
    
    # Main app flow
    if not st.session_state['authenticated']:
        show_login_signup()
    else:
        main_dashboard()

if __name__ == "__main__":
    main()