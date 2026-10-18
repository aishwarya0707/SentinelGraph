
from app.database import initialize_database, DATABASE_PATH

initialize_database()

print("Database file exists:", DATABASE_PATH.exists())
