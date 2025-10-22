#BlogWebApp

=== Features ===

- **User authentication & profiles** (register, login, logout, edit profile)  
- **CRUD posts**: Create, read, update, delete blog posts    
- **Responsive UI** (desktop & mobile friendly)   
- **User authorization & permissions** (only authors can edit/delete their own posts)  

---

=== Tech Stack ===

| Layer | Technology |
|-------|------------|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript, (optionally a frontend framework) |
| Database | SQLite |
| ORM / Migrations | SQLAlchemy / Flask-Migrate 
| Extensions / Libraries | Flask-Login, Flask-WTF, Flask-Migrate, etc. |
| Deployment | Heroku |

---

=-=-= Setup & Installation =-=-=

=== Prerequisites ===

-Python 3.x
-pip
-virtual environment tool (venv)
- Database (SQLite)

=== Installation Steps ===
1. Clone the repo:
  - git clone https://github.com/DimitarITZankov/BlogWebApp.git
  - cd BlogWebApp

2. Install dependencies:
   -pip install -r requirements.txt\

3. Initialize the database / run migrations :
   -flask db init
   -flask db migrate -m "Initial migration"
   -flask db upgrade

4.Run the application:
  -flask run
    OR
  -python3 app.py

5. Open your browser and go to:
   -http://127.0.0.1:5000
     OR (They are the same):
   -http://localhost:5000
