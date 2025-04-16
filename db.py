import os
import mysql.connector
from mysql.connector import Error

def get_db_connection():
    try:
        # for namecheap mysql database
        if os.environ.get("DB_PROVIDER") == "namecheap":
            return mysql.connector.connect(
                host=os.environ.get('DB_HOST'),  # Replace with your MySQL host
                user=os.environ.get('DB_USER'),  # Replace with your MySQL username
                password=os.environ.get('DB_PASS'),  # Replace with your MySQL password
                database=os.environ.get('DB_NAME')  # Replace with your database name
            )
        else:
            # Running locally or in a different environment
            return mysql.connector.connect(
                host='localhost',  # Replace with your local MySQL host
                user='root',  # Replace with your local MySQL username
                password='Onuchukwu12!',  # Replace with your local MySQL password
                database='stallionroutes'  # Replace with your local database name
            )
    except Error as err:
        print(f"Error: {err}")
        return None

""" # Running locally or in a different environment
    return mysql.connector.connect(
        # Replace with your Cloud SQL instance connection details
            host='localhost',
            user='root',
            password='Onuchukwu12!',
            database='stallionroutes'
        )
    

    if os.environ.get("GAE_ENV", "").startswith("standard") or os.environ.get("K_SERVICE"):
        # Running on Cloud Run or App Engine
        return mysql.connector.connect(
            host='35.246.3.253',  # Replace with your Cloud SQL instance IP address
            user=os.environ.get('DB_USER1'),  # Replace with your MySQL username
            password=os.environ.get('DB_PASS2'),  # Replace with your MySQL password
            database=os.environ.get('DB_NAME3'),  # Replace with your database name
            unix_socket=f"/cloudsql/{os.environ.get('DB_CONNECTION_NAME')}" # Replace with your Cloud SQL connection name
        )
"""