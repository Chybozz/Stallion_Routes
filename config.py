import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='stallionroutes-db.cnuw08cmoyx3.eu-north-1.rds.amazonaws.com',
        user='stallion_user',
        password='stallionroutes123!',
        database='stallionroutes-db'  # Replace with your database name
    )
