import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',  # stays localhost when using Cloud SQL Auth Proxy or when deploying with Cloud SQL integrated
        user='stallion_user',  # Replace with your MySQL username
        password='stallionroutes123',  # Replace with your MySQL password
        database='stallion_data'  # Replace with your database name
    )

# host='localhost',
# user='root',
# password='Onuchukwu12!',
# database='stallionroutes'