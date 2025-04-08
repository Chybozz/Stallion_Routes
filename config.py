import os
from dotenv import load_dotenv

class Config:
    MAIL_SERVER = 'smtp.gmail.com'  # Use the correct mail server
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('EMAIL_USER')  # Use the correct email
    MAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')  # Use the correct password
    MAIL_DEFAULT_SENDER = os.getenv('EMAIL_DEFAULT_SENDER')  # Use the correct email