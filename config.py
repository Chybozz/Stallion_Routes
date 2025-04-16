import os
import mysql.connector
from mysql.connector import Error

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Onuchukwu12!',
        database='stallionroutes'  # Replace with your database name
    )