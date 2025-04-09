import os
import mysql.connector
from mysql.connector import Error

def get_db_connection():
    try:
        return mysql.connector.connect(
            user=os.environ.get('DB_USER'),  # Replace with your MySQL username
            password=os.environ.get('DB_PASS'),  # Replace with your MySQL password
            database=os.environ.get('DB_NAME'),  # Replace with your database name
            unix_socket=f"/cloudsql/{os.environ.get('DB_CONNECTION_NAME')}" # Replace with your Cloud SQL connection name
        )
    except Error as err:
        print(f"Error: {err}")
        return None

# host='localhost',
# user='root',
# password='Onuchukwu12!',
# database='stallionroutes'