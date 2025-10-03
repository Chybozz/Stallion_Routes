import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='stallion_user',
        password='stallionroutes123!',
        database='stallionroutes-db'  # Replace with your database name
    )
