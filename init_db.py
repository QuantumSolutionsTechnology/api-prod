
import sqlite3
import uuid

conn = sqlite3.connect("api_keys.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS keys (
api_key TEXT PRIMARY KEY,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

test_api_key = str(uuid.uuid4())
cursor.execute("INSERT OR IGNORE INTO keys (api_key) VALUES (?)", (test_api_key,))

conn.commit()
conn.close()

print(f"Test API key generated: {test_api_key}")

