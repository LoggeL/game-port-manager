import sqlite3
import bcrypt
import sys
import os

DB_PATH = "/data/users.db"

def create_user(username, password):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    # Generate salt and hash
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # Re-create table just in case
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        print(f"User '{username}' created successfully.")
    except sqlite3.IntegrityError:
        # Update password if user already exists
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
        conn.commit()
        print(f"Password for user '{username}' updated successfully.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 create_user.py <username> <password>")
    else:
        create_user(sys.argv[1], sys.argv[2])
