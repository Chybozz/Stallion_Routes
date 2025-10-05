import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Onuchukwu12!',
        database='stallionroutes'  # Replace with your database name
    )