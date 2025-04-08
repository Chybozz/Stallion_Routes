import os
import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        user=os.environ.get('DB_USER'),  # Replace with your MySQL username
        password=os.environ.get('DB_PASS'),  # Replace with your MySQL password
        database=os.environ.get('DB_NAME'),  # Replace with your database name
        unix_socket=f"/cloudsql/{os.environ.get('DB_HOST')}"
    )

# host='localhost',
# user='root',
# password='Onuchukwu12!',
# database='stallionroutes'