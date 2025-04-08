import os
import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',  # stays localhost when using Cloud SQL Auth Proxy or when deploying with Cloud SQL integrated
        user=os.environ['DB_USER'],  # Replace with your MySQL username
        password=os.environ['DB_PASS'],  # Replace with your MySQL password
        database=os.environ['DB_NAME'],  # Replace with your database name
        unix_socket=f"/cloudsql/{os.environ['DB_HOST']}"
    )

# host='localhost',
# user='root',
# password='Onuchukwu12!',
# database='stallionroutes'