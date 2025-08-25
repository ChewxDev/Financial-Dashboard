PERSONAL FINANCE TRACKER
===============================================

This is a secure, standalone financial tracking application built with Streamlit.

FEATURES:
- User registration and secure login system
- Income and expense tracking
- Interactive charts and visualizations
- Category-based expense analysis
- Monthly financial overview
- Data stored locally in SQLite database
- No external dependencies or services required

SECURITY FEATURES:
- Password hashing with PBKDF2 and salt
- Input validation and sanitization
- SQL injection protection
- Secure session management
- Local data storage only

REQUIREMENTS:
- Python 3.7 or higher
- streamlit (>=1.28.0)
- pandas (>=2.0.0)
- plotly (>=5.17.0)

INSTALLATION & DEPLOYMENT:

1. For Local Development:
   pip install streamlit pandas plotly
   streamlit run app_standalone.py

2. For Streamlit Community Cloud:
   - Create GitHub repository
   - Upload app_standalone.py
   - Create requirements.txt with:
     streamlit>=1.28.0
     pandas>=2.0.0
     plotly>=5.17.0
   - Deploy via share.streamlit.io

3. For Other Cloud Platforms:
   The app uses SQLite database which creates a local file.
   For persistent storage on cloud platforms, ensure:
   - File system persistence is enabled
   - Write permissions for database file
   - Consider using cloud database for production

DATABASE:
- Uses SQLite (finance_tracker.db)
- Automatically created on first run
- Contains users, income, and expenses tables
- Foreign key constraints enabled
- Data validation at database level

USAGE:
1. Run the application
2. Create new account or login
3. Add income and expense entries
4. View analytics and insights
5. Export data if needed

DEPLOYMENT NOTES:
- App is completely self-contained
- No API keys or external services required
- Database file will be created in same directory
- User data is private and stored locally
- No analytics or tracking included

For production deployment, consider:
- Regular database backups
- HTTPS configuration
- Rate limiting for login attempts
- Log monitoring and alerting
