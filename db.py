import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',  # Replace with your MySQL username
        password='Onuchukwu12!',  # Replace with your MySQL password
        database='stallionroutes'  # Replace with your database name
    )