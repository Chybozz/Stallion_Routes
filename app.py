from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from email.message import EmailMessage
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS  # Import CORS
from db import get_db_connection  # Ensure this import is correct
from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import Error  # Add this import
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
import smtplib
import requests
import random
import string
import secrets
import os
import uuid

load_dotenv()  # Load the .env file

app = Flask(__name__)
secret_key = secrets.token_hex() # os.getenv('SECRET_KEY', secrets.token_hex())
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secret_key)
# app.config.from_object(Config)
# mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*") # Initialize SocketIO
CORS(app)  # Enable CORS

EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

PAYSTACK_SECRET_KEY = 'sk_test_4b450054ba0f838ba79c87463a462042c2a9736e' #e.g
"sk_live_4bb1aadf6285b8b9e2150f2836fbf930062576f3" # live key
""" request_id = secrets.token_hex(4)
print(f"Request ID: {request_id}") """

# Folder to store uploaded images
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def generate_request_id():
    connection = get_db_connection()
    cursor = connection.cursor()

    while True:
        prefix = ''.join(random.choices(string.ascii_uppercase, k=2))
        random_number = random.randint(1000000, 9999999)
        request_id = f"{prefix}-{random_number}"
    
        # Check if request_id already exists
        cursor.execute("SELECT COUNT(*) FROM delivery_requests WHERE request_id = %s", (request_id,))
        count = cursor.fetchone()[0]

        if count == 0:  # Unique ID found
            cursor.close()
            connection.close()
            return request_id

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/company')
def company():
    return render_template('company.html')

@app.route('/admins')
def admins():
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/rider_login', methods=['GET', 'POST'])
def rider_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        sqlInsert = "SELECT * FROM riders WHERE rider_email = %s"
        cursor.execute(sqlInsert, (email,))
        rider = cursor.fetchone()

        cursor.close()
        connection.close()

        if rider and check_password_hash(rider['password'], password): # Verify rider password
            if not rider['is_verified']:
                flash('Your email is not verified. Please check your email.', 'warning')
                return redirect(url_for('login'))
            session['rider_id'] = rider['rider_id']
            session['rider_full_name'] = rider['rider_name']
            session['rider_email'] = rider['rider_email']
            session['rider_phone'] = rider['rider_number']
            flash('Welcome back!', 'success')
            return redirect(url_for('rider_dashboard'))  # Create a dashboard route
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('rider_login'))
    return render_template('rider_login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        sqlInsert = "SELECT * FROM users WHERE email = %s AND role = 'customer'"
        cursor.execute(sqlInsert, (email,))
        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user and check_password_hash(user['password'], password): # Verify user password
            if not user['is_verified']:
                session['verify'] = "Not Verified"
            session['user_id'] = user['id']
            session['full_name'] = user['name']
            session['email'] = user['email']
            session['phone'] = user['phone']
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))  # Create a dashboard route
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/rider_signup', methods=['GET', 'POST'])
def rider_signup():
    if request.method == 'POST':
        rider_email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('rider_signup'))
        
        # Hash the password
        password_hash = generate_password_hash(password)

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            # Check if the email already exists
            cursor.execute("SELECT * FROM riders WHERE rider_email = %s", (rider_email,))
            existing_rider = cursor.fetchone()

            if existing_rider: 
                if existing_rider[5] == "":  # Assuming the password is in the 6th column (index 3)
                    flash('Email is already registered. Please log in or use a different email.', 'danger')
                    return redirect(url_for('rider_signup'))

            # Update riders with verified status
            cursor.execute("UPDATE riders SET password = %s WHERE rider_email = %s", (password_hash, rider_email))
            connection.commit()

            flash('Signup successful! Account Verified.', 'info')
            return redirect(url_for('rider_login'))
        except Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            connection.close()
    return render_template('rider_signup.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        # Hash the password
        password_hash = generate_password_hash(password)

        verification_token = str(uuid.uuid4())  # Generate a unique token

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            # Check if the email already exists
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash('Email is already registered. Please log in or use a different email.', 'danger')
                return redirect(url_for('signup'))

            # Insert user with unverified status
            cursor.execute("""
                INSERT INTO users (name, email, phone, password, verification_token, is_verified, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL 1 HOUR))
            """, (full_name, email, phone, password_hash, verification_token, False))
            connection.commit()

            # Create the verification link
            verification_url = f"{request.url_root}/verify/{verification_token}"
            body = f"Hi {full_name},\n\nPlease verify your email address by clicking the link below:\n{verification_url}\nThis link will expire in 1 hour.\n\nThank you for joining Stallion Routes!"
            
            # Prepare the email
            msg = EmailMessage()
            msg['Subject'] = 'Verify Your Email - Stallion Routes'
            msg['From'] = EMAIL_USER
            msg['To'] = email
            msg.set_content(body)

            # Send the email
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(EMAIL_USER, EMAIL_PASSWORD)
                smtp.send_message(msg)

            flash('Signup successful! Please check your email to verify your account.', 'info')
            return redirect(url_for('login'))
        except Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            connection.close()
    return render_template('signup.html')

@app.route('/verify/<token>')
def verify_email(token):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT id FROM users WHERE verification_token = %s AND is_verified = %s AND expires_at > NOW()", (token, False))
        user = cursor.fetchone()

        if user:
            # Mark the user as verified
            cursor.execute("UPDATE users SET is_verified = %s, verification_token = NULL WHERE id = %s", (True, user[0]))
            connection.commit()
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired verification link.', 'danger')
            return redirect(url_for('signup'))
    finally:
        cursor.close()
        connection.close()

@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    if request.method == 'POST':
        email = session['email']
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and not user['is_verified']:  # Check if the user is not verified
                verification_token = str(uuid.uuid4())
                cursor.execute("UPDATE users SET verification_token = %s, expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE email = %s", (verification_token, email))
                connection.commit()

                # Create the verification link
                verification_url = f"{request.url_root}/verify/{verification_token}"
                body = f"Hi,\n\nPlease verify your email address by clicking the link below:\n{verification_url}\nThis link will expire in 1 hour.\n\nThank you!"
                
                # Prepare the email
                msg = EmailMessage()
                msg['Subject'] = 'Resend Verification - Stallion Routes'
                msg['From'] = EMAIL_USER
                msg['To'] = email
                msg.set_content(body)

                # Send the email
                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                    smtp.login(EMAIL_USER, EMAIL_PASSWORD)
                    smtp.send_message(msg)

                flash('Verification link resent! Please check your email.', 'info')
            else:
                flash('Email not found or already verified.', 'danger')
        except Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            connection.close()
    return redirect(url_for('customer_settings'))

@app.route('/rider_forgot_password', methods=['GET', 'POST'])
def rider_forgot_password():
    if request.method == 'POST':
        rider_email = request.form['email']
        session['stallionriders'] = "stallionriders"

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute("SELECT * FROM riders WHERE rider_email = %s", (rider_email,))
            rider = cursor.fetchone()

            if rider:
                # Generate a password reset token
                reset_token = str(uuid.uuid4())

                # Store the token in the database
                cursor.execute("""
                    INSERT INTO password_reset (email, reset_token, expires_at)
                    VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL 1 HOUR))
                """, (rider_email, reset_token))
                connection.commit()

                # ON DUPLICATE KEY UPDATE reset_token = %s, expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR)

                # Send password reset email
                reset_url = f"{request.url_root}/reset_password/{reset_token}"
                
                msg = EmailMessage()
                msg['Subject'] = 'Password Reset Request - Stallion Routes'
                msg['From'] = EMAIL_USER
                msg['To'] = rider_email
                msg.set_content(f"Hi,\n\nTo reset your password, please click the link below:\n{reset_url}\nThis link will expire in 1 hour.\n\nThank you!")

                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                    smtp.login(EMAIL_USER, EMAIL_PASSWORD)
                    smtp.send_message(msg)

                flash('Password reset link sent to your email.', 'info')
            else:
                flash('Email not found.', 'danger')
        except Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            connection.close()
    return render_template('forgot_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                # Generate a password reset token
                reset_token = str(uuid.uuid4())

                # Store the token in the database
                cursor.execute("""
                    INSERT INTO password_reset (email, reset_token, expires_at)
                    VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL 1 HOUR))
                """, (email, reset_token))
                connection.commit()

                # Send password reset email
                reset_url = f"{request.url_root}/reset_password/{reset_token}"
                
                msg = EmailMessage()
                msg['Subject'] = 'Password Reset Request - Stallion Routes'
                msg['From'] = EMAIL_USER
                msg['To'] = email
                msg.set_content(f"Hi,\n\nTo reset your password, please click the link below:\n{reset_url}\nThis link will expire in 1 hour.\n\nThank you!")

                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                    smtp.login(EMAIL_USER, EMAIL_PASSWORD)
                    smtp.send_message(msg)

                flash('Password reset link sent to your email.', 'info')
            else:
                flash('Email not found.', 'danger')
        except Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            connection.close()
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_password', token=token))

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            if session.get('stallionriders') == "stallionriders":
                cursor.execute("SELECT email FROM password_reset WHERE reset_token = %s AND reset_token IS NOT NULL AND expires_at > NOW()", (token,))
                rider = cursor.fetchone()

                if rider:
                    # Hash the new password
                    password_hash = generate_password_hash(new_password)

                    # Update the password and clear the reset token
                    cursor.execute("UPDATE riders SET password = %s WHERE rider_email = %s", (password_hash, rider[0]))
                    connection.commit()

                    flash('Password reset successfully! You can now log in.', 'success')
                    return redirect(url_for('rider_login'))
                else:
                    flash('Invalid or expired reset link.', 'danger')
                    return redirect(url_for('rider_forgot_password'))
            else:
                cursor.execute("SELECT email FROM password_reset WHERE reset_token = %s AND reset_token IS NOT NULL AND expires_at > NOW()", (token,))
                user = cursor.fetchone()

                if user:
                    # Hash the new password
                    password_hash = generate_password_hash(new_password)

                    # Update the password and clear the reset token
                    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (password_hash, user[0]))
                    connection.commit()

                    flash('Password reset successfully! You can now log in.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Invalid or expired reset link.', 'danger')
                    return redirect(url_for('forgot_password'))
        except Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            connection.close()
    return render_template('reset_password.html', token=token)

@app.route('/request_delivery', methods=['POST'])
def request_delivery():
    if request.method == 'POST':
        try:
            # user_id = session.get('user_id')
            request_id = generate_request_id()
            session['request_id'] = request_id
            delivery_type = request.form['delivery_type']

            if delivery_type == 'waybill':
                waybillpackDesc = request.form.get('waybillpackDesc')
                waybilldeliveryaddress = request.form.get('waybilldeliveryaddress')
                waybillpackworth = request.form.get('waybillpackworth')
                waybillpickupnumber = request.form.get('waybillpickupnumber')
                waybillpickupaddress = request.form.get('waybillpickupaddress')
                waybillbusno = request.form.get('waybillbusno')
                waybilldeliverystate = request.form.get('waybilldeliverystate')

                if not all([waybillpackDesc, waybilldeliveryaddress, waybillpackworth, waybillpickupnumber, waybillpickupaddress, waybilldeliverystate]):
                    return jsonify({'error': 'Please fill all fields', 'status': 'danger'}), 400

                return jsonify({
                    'request_id': request_id,
                    'delivery_type': delivery_type,
                    'waybillpackDesc': waybillpackDesc,
                    'waybilldeliveryaddress': waybilldeliveryaddress,
                    'waybillpackworth': waybillpackworth,
                    'waybillpickupnumber': waybillpickupnumber,
                    'waybillpickupaddress': waybillpickupaddress,
                    'waybillbusno': waybillbusno,
                    'waybilldeliverystate': waybilldeliverystate
                }), 200

            elif delivery_type == 'handoff':
                handoffrecipientname = request.form.get('handoffrecipientname')
                handoffrecipientnumber = request.form.get('handoffrecipientnumber')
                handoffpickupaddress = request.form.get('handoffpickupaddress')
                handoffrecipientaddress = request.form.get('handoffrecipientaddress')
                handoffpackageItem = request.form.get('handoffpackageItem')
                handoffpackworth = request.form.get('handoffpackworth')
                handoffdeliverystate = request.form.get('handoffdeliverystate')

                if not all([handoffrecipientname, handoffrecipientnumber, handoffpickupaddress, handoffrecipientaddress, handoffpackageItem, handoffpackworth, handoffdeliverystate]):
                    return jsonify({'error': 'Please fill all fields', 'status': 'danger'}), 400

                return jsonify({
                    'request_id': request_id,
                    'delivery_type': delivery_type,
                    'handoffrecipientname': handoffrecipientname,
                    'handoffrecipientnumber': handoffrecipientnumber,
                    'handoffpickupaddress': handoffpickupaddress,
                    'handoffrecipientaddress': handoffrecipientaddress,
                    'handoffpackageItem': handoffpackageItem,
                    'handoffpackworth': handoffpackworth,
                    'handoffdeliverystate': handoffdeliverystate
                }), 200

            elif delivery_type == 'food':
                restaurantname = request.form.get('restaurantname')
                restaurantrecptname = request.form.get('restaurantrecptname')
                restaurantrecptnumber = request.form.get('restaurantrecptnumber')
                restaurantaddress = request.form.get('restaurantaddress') 
                fooddeliveryaddress = request.form.get('fooddeliveryaddress')
                foodItem = request.form.get('foodItem')
                foodworth = request.form.get('foodworth')
                fooddeliverystate = request.form.get('fooddeliverystate')

                if not all([restaurantname, restaurantrecptname, restaurantrecptnumber, restaurantaddress, fooddeliveryaddress, foodItem, foodworth, fooddeliverystate]):
                    return jsonify({'error': 'Please fill all fields', 'status': 'danger'}), 400

                return jsonify({
                    'request_id': request_id,
                    'delivery_type': delivery_type,
                    'restaurantname': restaurantname,
                    'restaurantrecptname': restaurantrecptname,
                    'restaurantrecptnumber': restaurantrecptnumber,
                    'restaurantaddress': restaurantaddress,
                    'fooddeliveryaddress': fooddeliveryaddress,
                    'foodItem': foodItem,
                    'foodworth': foodworth,
                    'fooddeliverystate': fooddeliverystate
                }), 200

        except Exception as e:
            return jsonify({'error': str(e), 'status': 'danger'}), 500

    return jsonify({'message': 'Delivery request submitted successfully!', 'status': 'success'}), 200

@app.route('/request_payment', methods=["GET", "POST"])
def request_payment():
    if request.is_json:
        # Retrieve data from the request form or JSON payload
        data = request.get_json()

        # Check if data is received properly
        if not data:
            return jsonify({'error': 'No data received'}), 400

        # Get data from the JSON payload
        delivery_type = data.get('delivery_type')
        request_id = data.get('request_id')
        customer_id = data.get('customer_id')
        customer_name = data.get('customer_name')
        customer_mail = data.get('customer_mail')
        customer_number = data.get('customer_number')
        pickup_location = data.get('pickup_location')
        delivery_address = data.get('delivery_address')
        package_description = data.get('package_description')
        package_worth = data.get('package_worth')
        transaction_date = data.get('transaction_date')
        transaction_time = data.get('transaction_time')
        transport_fee = data.get('transport_fee')
        state = data.get('state')

        # Initialize optional fields
        pickup_number = bus_number = recipient_name = recipient_number = restaurant_name = None

        if delivery_type == 'waybill':
            pickup_number = data.get('pickup_number')
            bus_number = data.get('bus_number')
        elif delivery_type == 'handoff':
            recipient_name = data.get('recipient_name')
            recipient_number = data.get('recipient_number')
        elif delivery_type == 'food':
            restaurant_name = data.get('restaurant_name')
            recipient_name = data.get('recipient_name')
            recipient_number = data.get('recipient_number')

        # Convert bus_number_str to the format "BUS-123"
        # bus_number = f"BUS-{bus_number_str}"
        # Amount parameter
        # Remove commas from the transport fee string and convert to float
        transport_fee = data['transport_fee'].replace(',', '')
        amount = int(float(transport_fee) * 100)  # Amount in kobo

        package_worth = data['package_worth'].replace(',', '')

        # Ensure all required fields are filled
        required_fields = [request_id, customer_id, customer_name, customer_mail, customer_number, pickup_location, delivery_address, 
                           package_description, package_worth, state, transaction_date, transaction_time]
        if delivery_type == 'waybill':
            required_fields.extend([pickup_number])
        elif delivery_type == 'handoff':
            required_fields.extend([recipient_name, recipient_number])
        elif delivery_type == 'food':
            required_fields.extend([restaurant_name, recipient_name, recipient_number])
        if not all(required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Save the delivery request
        # new_request = DeliveryRequest(request_id, package_description, delivery_address, package_worth, driver_no, pickup_location, bus_number, transaction_date, transaction_time)
        # delivery_requests.append(new_request)

        # connection = get_db_connection()

        # Step 1: Initialize a payment session with Paystack
        paystack_url = 'https://api.paystack.co/transaction/initialize'
        
        # Create the payload with customer details and amount
        headers = {
            'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
            'Content-Type': 'application/json',
        }
        
        # Paystack requires the amount in kobo (for NGN), so multiply the package worth by 100
        paystack_data = {
            'email': customer_mail,  # You can capture the user's email or use a placeholder
            'amount': amount,  # Convert package_worth to kobo
            'callback_url': url_for('payment_callback', _external=True),  # Callback after successful payment
            'metadata': {
                'delivery_type': delivery_type,
                'request_id': request_id,
                'customer_name': customer_name,
                'customer_id': customer_id,
                'customer_mail': customer_mail,
                'customer_number': customer_number,
                'pickup_location': pickup_location,
                'delivery_address': delivery_address,
                'package_description': package_description,
                'package_worth': package_worth,
                'state': state,
                'transaction_date': transaction_date,
                'transaction_time': transaction_time,
                'transport_fee': transport_fee,
            }
        }

        # Add delivery-type-specific data
        if delivery_type == 'waybill':
            paystack_data['metadata']['pickup_number'] = pickup_number
            paystack_data['metadata']['bus_number'] = bus_number
        elif delivery_type == 'handoff':
            paystack_data['metadata']['recipient_name'] = recipient_name
            paystack_data['metadata']['recipient_number'] = recipient_number
        elif delivery_type == 'food':
            paystack_data['metadata']['restaurant_name'] = restaurant_name
            paystack_data['metadata']['recipient_name'] = recipient_name
            paystack_data['metadata']['recipient_number'] = recipient_number
        
        # Step 2: Send the request to Paystack API
        try:
            paystack_response = requests.post(paystack_url, json=paystack_data, headers=headers)
            paystack_response_data = paystack_response.json()
            
            if paystack_response_data['status'] == True:
                # Paystack transaction initialized successfully
                payment_url = paystack_response_data['data']['authorization_url']
                
                # Redirect the user to the Paystack payment page
                return jsonify({'payment_url': payment_url}), 200
            else:
                return jsonify({'error': 'Payment initialization failed', 'message': paystack_response_data['message']}), 400

        except Exception as e:
            return jsonify({'error': 'Failed to initialize payment', 'message': str(e)}), 500

    return jsonify({'error': 'Invalid request format'}), 400

@app.route('/payment_callback', methods=['GET'])
def payment_callback():
    # Paystack transaction reference
    reference = request.args.get('reference')

    # Verify the transaction with Paystack API
    paystack_url = f'https://api.paystack.co/transaction/verify/{reference}'
    headers = {
        'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json',
    }

    # Step 1: Verify the payment
    try:
        response = requests.get(paystack_url, headers=headers)
        payment_data = response.json()
        
        if payment_data['status'] == True and payment_data['data']['status'] == 'success':
            # Payment was successful
            metadata = payment_data['data']['metadata']

            # Insert the delivery request into the database
            connection = get_db_connection()

            try:
                with connection.cursor() as cursor:
                    if metadata['delivery_type'] == 'waybill':
                        cursor.execute("""
                            INSERT INTO delivery_requests 
                            (request_id, customer_id, type, customer_name, customer_email, customer_number, package_desc, delivery_address, 
                            worth, pickup_number, pickup_address, bus_number, state, date_requested, time_requested)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (metadata['request_id'], metadata['customer_id'], metadata['delivery_type'], metadata['customer_name'], metadata['customer_mail'], metadata['customer_number'], 
                            metadata['package_description'], metadata['delivery_address'], metadata['package_worth'], metadata['pickup_number'], metadata['pickup_location'], 
                            metadata['bus_number'], metadata['state'], metadata['transaction_date'], metadata['transaction_time']))
                        cursor.execute("""
                            INSERT INTO transactions (request_id, amount)
                            VALUES (%s, %s)
                        """, (metadata['request_id'], metadata['transport_fee']))

                    elif metadata['delivery_type'] == 'handoff':
                        cursor.execute("""
                            INSERT INTO delivery_requests 
                            (request_id, customer_id, type, customer_name, customer_email, customer_number, recipient_name, recipient_number, 
                            package_desc, delivery_address, worth, pickup_address, state, date_requested, time_requested)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (metadata['request_id'], metadata['customer_id'], metadata['delivery_type'], metadata['customer_name'], metadata['customer_mail'], metadata['customer_number'], 
                            metadata['recipient_name'], metadata['recipient_number'], metadata['package_description'], metadata['delivery_address'], metadata['package_worth'], 
                            metadata['pickup_location'], metadata['state'], metadata['transaction_date'], metadata['transaction_time']))
                        cursor.execute("""
                            INSERT INTO transactions (request_id, amount)
                            VALUES (%s, %s)
                        """, (metadata['request_id'], metadata['transport_fee']))

                    elif metadata['delivery_type'] == 'food':
                        cursor.execute("""
                            INSERT INTO delivery_requests 
                            (request_id, customer_id, type, customer_name, customer_email, customer_number, recipient_name, recipient_number, 
                            restaurant_name, package_desc, delivery_address, worth, pickup_address, state, date_requested, time_requested)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (metadata['request_id'], metadata['customer_id'], metadata['delivery_type'], metadata['customer_name'], metadata['customer_mail'], metadata['customer_number'], 
                            metadata['recipient_name'], metadata['recipient_number'], metadata['restaurant_name'], metadata['package_description'], metadata['delivery_address'], 
                            metadata['package_worth'], metadata['pickup_location'], metadata['state'], metadata['transaction_date'], metadata['transaction_time']))
                        cursor.execute("""
                            INSERT INTO transactions (request_id, amount)
                            VALUES (%s, %s)
                        """, (metadata['request_id'], metadata['transport_fee']))
                    connection.commit()
                    
                    # Emit a notification for new delivery requests
                    # socketio.emit('request_confirmed', {'request_id': request_id}, broadcast=True)
                    socketio.emit('new_delivery_request', {'message': 'A new delivery request has been made!'})
                    
                    # Redirect the user back to the customer page or wherever necessary
                    return redirect(url_for('dashboard'))
                    
                    # return jsonify({'success': True, 'message': 'Request saved successfully!'}), 200

            except Exception as e:
                connection.rollback()
                return jsonify({'error': str(e)}), 500

            finally:
                connection.close()
        else:
            # Payment failed or was incomplete
            return jsonify({'error': 'Payment failed or incomplete'}), 400

    except Exception as e:
        return jsonify({'error': 'Failed to verify payment', 'message': str(e)}), 500

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == "POST" and request.is_json:
        data = request.get_json()
        request_id = data.get('reqID')
        action = data.get('action')

        if request_id and action:
            try:
                connection = get_db_connection()
                cursor = connection.cursor()

                if action == 'confirm':
                    cursor.execute("""
                        UPDATE delivery_requests SET status = %s WHERE request_id = %s
                    """, ("delivered", request_id))
                    
                    cursor.execute("""
                        UPDATE transactions SET status = %s WHERE request_id = %s
                    """, ("completed", request_id))
                    connection.commit()

                    return jsonify({'success': True, 'message': 'Delivery Confirmed successfully!'})

                elif action == 'track':
                    return jsonify({'success': True, 'message': 'Package tracking feature is not implemented yet.'})

            except Exception as e:
                return jsonify({'success': False, 'message': f'Error: {str(e)}'})
            finally:
                cursor.close()
                connection.close()
        
        return jsonify({'success': False, 'message': 'No request ID or action provided'})

    customer_id = session.get('user_id')
    customer_name = session['full_name']
    customer_email = session['email']
    customer_phone = session['phone']

    # Get current date and time
    current_date = datetime.now().strftime('%Y-%m-%d')  # e.g. '2024-09-19'
    current_time = datetime.now().strftime('%H:%M:%S')  # e.g. '14:30:55'

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT dr.request_id, dr.type, dr.recipient_name, dr.recipient_number, dr.restaurant_name, 
                dr.pickup_address, dr.delivery_address, dr.package_desc, dr.date_requested, 
                dr.time_requested, dr.status, tr.rider_name, tr.rider_number
            FROM delivery_requests dr 
            LEFT JOIN transactions tr ON dr.request_id = tr.request_id
            WHERE (dr.status IN ('pending', 'in transit') OR tr.status = 'accepted') 
            AND customer_id = %s
        """, (customer_id,))
        pending_requests = cursor.fetchall()
    connection.close()
    return render_template('dashboard.html', customer_id=customer_id, customer_name=customer_name, customer_email=customer_email, 
                        customer_phone=customer_phone, current_date=current_date, current_time=current_time, 
                        pending_requests=pending_requests)

@app.route('/submit-rating', methods=["POST"])
def submit_rating():
    if request.is_json:
        data = request.get_json()
        req_id = data.get('reqID')
        rider_name = data.get('riderName')
        rating = data.get('rating')
        feedback = data.get('feedback')

        if not req_id or not rating:
            return jsonify({'success': False, 'message': 'Request ID and rating are required.'})

        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO rider_ratings (request_id, rider_name, rating, feedback) 
                VALUES (%s, %s, %s, %s)
            """, (req_id, rider_name, rating, feedback))
            connection.commit()
            return jsonify({'success': True, 'message': 'Rating submitted successfully.'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error: {str(e)}'})
        finally:
            cursor.close()
            connection.close()
    return jsonify({'success': False, 'message': 'Invalid data.'})

@app.route('/customer_settings', methods=['GET', 'POST'])
def customer_settings():
    if 'user_id' not in session:
        # return jsonify({'error': 'Not logged in'}), 401  # Return an error if not logged in
        return redirect(url_for('login'))  # Redirect if not logged in
    
    # Fallback to render template on GET or non-JSON POST
    customer_id = session.get('user_id')
    customer_name = session.get('full_name')
    customer_email = session.get('email')
    customer_phone = session.get('phone')
    
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')

    if request.method == "POST":
        customer_name = request.form['customer_name']
        customer_email = request.form['customer_email']
        customer_password = request.form['customer_password']
        customer_number = request.form['customer_number']

        # customer_name = request.form.get('customer_name', '').strip()
        # customer_email = request.form.get('customer_email', '').strip()
        # customer_password = request.form.get('customer_password', '').strip()
        # customer_number = request.form.get('customer_number', '').strip()

        if not all([customer_name, customer_email, customer_password, customer_number]):
            flash("All fields are required!", "danger")
            return redirect(url_for('customer_settings'))

        # Hash the password
        if not customer_password:
                flash("Password cannot be empty!", "danger")
                return redirect(url_for('customer_settings'))
        
        password_hash = generate_password_hash(customer_password)

        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute("""UPDATE users SET name = %s, email = %s, password = %s, 
                            phone = %s WHERE id = %s""", 
                        (customer_name, customer_email, password_hash, customer_number, customer_id))
            connection.commit()
            flash("Updated successfully!", "success")
        except Exception as e:
            connection.rollback()
            flash(f"Error updating profile: {str(e)}", "danger")
        finally:
            cursor.close()
            connection.close()

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT is_verified FROM users WHERE id = %s AND email = %s
        """, (customer_id, customer_email))
        account_verified = cursor.fetchone()
    connection.close()

    if account_verified:
        account_verified = account_verified[0]

    return render_template('customer_settings.html', customer_id=customer_id, customer_name=customer_name, customer_email=customer_email, 
                           customer_phone=customer_phone, current_date=current_date, current_time=current_time, account_verified=account_verified)

@app.route('/rider_dashboard', methods=['GET', 'POST'])
def rider_dashboard():
    if 'rider_id' not in session:
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('rider_login'))

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            reqID = data.get('reqID')
            action = data.get('action')
            riderId = data.get('rider_id')
            riderName = data.get('rider_name')
            riderPhone = data.get('rider_phone')
            tranDate = data.get('transaction_date')
            tranTime = data.get('transaction_time')

            if not reqID or not action:
                return jsonify({'success': False, 'message': 'No request ID or action provided'})
            
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:

                    if action == 'accept':
                        # Handle accept request
                        cursor.execute("""
                            UPDATE delivery_requests SET rider_id = %s, status = 'in transit'
                            WHERE request_id = %s
                        """, (riderId, reqID,))

                        cursor.execute("""
                            UPDATE transactions SET status = 'accepted', rider_id = %s, rider_name = %s, rider_number = %s, 
                                        transaction_date = %s, transaction_time = %s
                            WHERE request_id = %s
                        """, (riderId, riderName, riderPhone, tranDate, tranTime, reqID))
                        connection.commit()
                        return jsonify({'success': True, 'message': 'Request accepted successfully!'})
                    elif action == 'track':
                        # Handle track package request
                        # Implement tracking logic here
                        return jsonify({'success': True, 'message': 'Tracking package feature not implemented yets...'})
                    else:
                        return jsonify({'success': False, 'message': 'Invalid action'})
            except Error as e:
                return jsonify({'success': False, 'message': str(e)})
            finally:
                connection.close()
        return jsonify({'success': False, 'message': 'Invalid request format'})
    
    rider_id = session.get('rider_id')
    rider_name = session['rider_full_name']
    rider_email = session['rider_email']
    rider_phone = session['rider_phone']

    # Get current date and time
    current_date = datetime.now().strftime('%Y-%m-%d')  # e.g. '2024-09-19'
    current_time = datetime.now().strftime('%H:%M:%S')  # e.g. '14:30:55'

    connection = get_db_connection()
    with connection.cursor() as cursor:
        # Get the rider's state
        cursor.execute("SELECT state FROM riders WHERE rider_id = %s", (rider_id,))
        riderState = cursor.fetchone()

        if not riderState:
            flash("Rider not found!", "danger")
            return redirect(url_for('login'))

        state = riderState[0]

        # Get all pending delivery requests
        cursor.execute("""
            SELECT request_id, type, customer_name, customer_number, recipient_name, recipient_number, restaurant_name, 
                pickup_address, delivery_address, package_desc, date_requested, 
                time_requested, status, state
            FROM delivery_requests
            WHERE (status IN ('pending')) AND state = %s
        """, (state,))
        delivery_requests = cursor.fetchall()

        # Get all accepted delivery requests
        cursor.execute("""
            SELECT dr.request_id, dr.type, dr.customer_name, dr.customer_number, dr.recipient_name, dr.recipient_number, 
                dr.restaurant_name, dr.pickup_address, dr.delivery_address, dr.package_desc, dr.date_requested, 
                dr.time_requested, tr.status
            FROM delivery_requests dr
            LEFT JOIN transactions tr ON dr.request_id = tr.request_id
            WHERE dr.status = 'in transit' AND tr.rider_id = %s
        """, (rider_id,))
        accepted_requests = cursor.fetchall()

        # Get all completed delivery
        cursor.execute("""
            SELECT dr.request_id, dr.type, dr.customer_name, tr.status
            FROM delivery_requests dr
            LEFT JOIN transactions tr ON dr.request_id = tr.request_id
            WHERE dr.status = 'delivered' AND tr.rider_id = %s
        """, (rider_id,))
        completed_deliveries = cursor.fetchall()
    connection.close()

    return render_template('rider_dashboard.html', rider_id=rider_id, rider_name=rider_name, rider_email=rider_email, rider_phone=rider_phone, 
                           current_date=current_date, current_time=current_time, delivery_requests=delivery_requests, 
                           accepted_requests=accepted_requests, completed_deliveries=completed_deliveries)

@app.route('/deliver', methods=['POST'])
def deliver():
    if request.is_json:
        data = request.get_json()
        request_id = data.get('reqID')
        action = data.get('action')

        if not request_id or not action:
            return jsonify({'success': False, 'message': 'No request ID or action provided'})

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            if action == 'deliver': 
                cursor.execute("""
                    UPDATE transactions SET status = %s WHERE request_id = %s
                """, ("awaiting confirmation", request_id))
                connection.commit()

                return jsonify({'success': True, 'message': 'Delivered successfully!'})

            elif action == 'track':
                return jsonify({'success': True, 'message': f'Package tracking feature for {request_id} is not implemented yet.'})

            else:
                return jsonify({'success': False, 'message': 'Invalid action'})

        except Exception as e:
            return jsonify({'success': False, 'message': f'Error: {str(e)}'})

        finally:
            cursor.close()
            connection.close()

    return jsonify({'success': False, 'message': 'Invalid request format'})

@app.route('/rider_settings', methods=['GET', 'POST'])
def rider_settings():
    if 'rider_id' not in session:
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('rider_login')) # Redirect if not logged in
    
    # Fallback to render template on GET or non-JSON POST
    rider_id = session.get('rider_id')
    rider_name = session.get('rider_full_name')
    rider_email = session.get('rider_email')
    rider_phone = session.get('rider_phone')
    
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')

    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT rider_photo FROM riders WHERE rider_email= %s"
        cursor.execute(sql, (rider_email,))
        filename = cursor.fetchone()
        if filename:
            filename = filename[0]
    connection.close()

    if request.method == "POST":
        rider_name = request.form['rider_name']
        rider_email = request.form['rider_email']
        rider_password = request.form['rider_password']
        rider_number = request.form['rider_number']

        if not all([rider_name, rider_email, rider_password, rider_number]):
            flash("All fields are required!", "danger")
            return redirect(url_for('rider_settings'))

        # Hash the password
        if not rider_password:
                flash("Password cannot be empty!", "danger")
                return redirect(url_for('rider_settings'))
        
        password_hash = generate_password_hash(rider_password)

        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute("""UPDATE riders SET rider_name = %s, rider_email = %s, password = %s, 
                            rider_number = %s WHERE id = %s""", 
                        (rider_name, rider_email, password_hash, rider_number, rider_id))
            connection.commit()
            flash("Updated successfully!", "success")
        except Exception as e:
            connection.rollback()
            flash(f"Error updating profile: {str(e)}", "danger")
        finally:
            cursor.close()
            connection.close()

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT is_verified FROM riders WHERE id = %s AND rider_email = %s
        """, (rider_id, rider_email))
        account_verified = cursor.fetchone()
    connection.close()

    if account_verified:
        account_verified = account_verified[0]

    return render_template('rider_settings.html', rider_id=rider_id, rider_name=rider_name, rider_email=rider_email, 
            rider_phone=rider_phone, filename=filename, current_date=current_date, current_time=current_time, account_verified=account_verified)

# Function to check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/update_profile_picture', methods=['POST'])
def update_profile_picture():
    if 'rider_id' not in session:
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('rider_login'))
    
    # Fallback to render template on GET or non-JSON POST
    rider_id = session.get('rider_id')
    rider_name = session.get('rider_full_name')
    rider_email = session.get('rider_email')
    rider_phone = session.get('rider_phone')
    
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')

    uploaded_filename = None  # Default is None

    if request.method == "POST":
        # Check if file is present in request
        if 'profile_pictures' not in request.files:
            return render_template('rider_settings.html', error="No file part")

        file = request.files['profile_pictures']
        
        if file.filename == '':
            return render_template('rider_settings.html', error="No selected file")

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)  # Save file to folder

            uploaded_filename = filename

            # Get logged-in rider ID from session (example)
            rider_id = session.get('rider_id')

            # Store filename in the database
            connection = get_db_connection()
            cursor = connection.cursor()
            update_query = "UPDATE riders SET rider_photo = %s WHERE id = %s"
            cursor.execute(update_query, (filename, rider_id))
            connection.commit()

            return redirect(url_for('rider_settings'))  # Redirect to profile page

        return "File type not allowed"

    return render_template('rider_settings.html',rider_id=rider_id, rider_name=rider_name, rider_email=rider_email, 
            rider_phone=rider_phone, filename=uploaded_filename, current_date=current_date, current_time=current_time)

@app.route('/admin')
def admin():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT * FROM users WHERE role='customer'"
        cursor.execute(sql)
        customers = cursor.fetchall()
        sql = "SELECT * FROM users WHERE role='rider'"
        cursor.execute(sql)
        riders = cursor.fetchall()

        # Select new_deliveries details
        cursor.execute("""
            SELECT dr.id, dr.request_id, dr.customer_id, dr.customer_name, dr.customer_number, dr.rider_id, dt.rider_name, dt.rider_number, dr.type, 
                dr.recipient_name, dr.recipient_number, dr.restaurant_name, dr.package_desc, dr.pickup_address, dr.delivery_address, dr.worth, 
                dr.pickup_number, dr.date_requested, dr.time_requested, dr.status
            FROM delivery_requests dr
            LEFT JOIN transactions dt ON dr.request_id = dt.request_id
            WHERE dr.status = 'pending' OR dr.status = 'in transit'
        """)
        new_deliveries = cursor.fetchall()

        # Select completed_deliveries details
        cursor.execute("""
            SELECT dr.id, dr.request_id, dr.customer_id, dr.customer_name, dr.customer_number, dr.rider_id, dt.rider_name, dt.rider_number, dr.type, 
                dr.recipient_name, dr.recipient_number, dr.restaurant_name, dr.package_desc, dr.pickup_address, dr.delivery_address, dr.worth, 
                dr.pickup_number, dr.date_requested, dr.time_requested, dr.status
            FROM delivery_requests dr
            LEFT JOIN transactions dt ON dr.request_id = dt.request_id
            WHERE dr.status = 'delivered'
        """)
        delivered_requests = cursor.fetchall()

        # Select transaction details
        cursor.execute("""
            SELECT dr.request_id, dr.customer_id, dr.customer_name, dr.customer_number, dr.rider_id, dt.rider_name, 
                dt.rider_number, dr.type, dt.amount, dt.transaction_date, dt.transaction_time, dt.status
            FROM delivery_requests dr
            LEFT JOIN transactions dt ON dr.request_id = dt.request_id
            WHERE dt.status = 'accepted' OR dt.status = 'awaiting confirmation' OR dt.status = 'completed'
        """)
        tran_details = cursor.fetchall()
    connection.close()

    return render_template('admin.html', customers=customers, riders=riders, new_deliveries=new_deliveries, 
                           delivered_requests=delivered_requests, tran_details=tran_details)

@app.route('/admin_rider', methods=['GET', 'POST'])
def admin_rider():
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')
    
    # Initialize table_data to avoid undefined errors
    table_data = []
    
    # If GET request, retrieve table_data from database
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    # Select delivery requests data
    cursor.execute("SELECT * FROM delivery_requests")  # Replace your_table_name with the actual table
    table_data = cursor.fetchall()

    # Select rider's details
    cursor.execute("""
        SELECT id, rider_id, rider_name, rider_email, rider_number, 
            rider_address, city, state, account_number, bank_name
        FROM riders
    """)
    rider_data = cursor.fetchall()

    cursor.close()
    connection.close()
    
    if request.method == 'POST':
        # Retrieve form data
        form_data = {
            'rider_name': request.form['rider_name'],
            'rider_email': request.form['rider_email'],
            'rider_number': request.form['rider_number'],
            'rider_age': request.form['rider_age'],
            'residential_address': request.form['residential_address'],
            'rider_city': request.form['rider_city'],
            'rider_state': request.form['rider_state'],
            'acct_num': request.form['acct_num'],
            'bank_name': request.form['bank_name'],
            'guarantor_name': request.form['guarantor_name'],
            'guarantor_number': request.form['guarantor_number'],
            'guarantor_residential_address': request.form['guarantor_residential_address'],
            'guarantor_relationship': request.form['guarantor_relationship'],
            'guarantor_occupation': request.form['guarantor_occupation'],
            'guarantor_state': request.form['guarantor_state']
        }
        
        # Connect to database and check for duplicates
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            # Check if the email, rider phone, or guarantor phone already exists
            cursor.execute("SELECT * FROM riders WHERE rider_email = %s OR rider_number = %s OR guarantor_number = %s OR account_number = %s", 
                           (form_data['rider_email'], form_data['rider_number'], form_data['guarantor_number'], form_data['acct_num']))
            rider = cursor.fetchone()

            if rider:
                if rider['rider_email'] == form_data['rider_email']:
                    flash("Email already registered!", "danger")
                elif rider['rider_number'] == form_data['rider_number']:
                    flash("Rider Phone Number already registered!", "danger")
                elif rider['guarantor_number'] == form_data['guarantor_number']:
                    flash("Guarantor Phone Number already registered!", "danger")
                
                # Return to the form with pre-filled data
                return render_template('admin_rider.html', form_data=form_data, table_data=table_data, rider_data=rider_data, current_date=current_date, current_time=current_time)
            
            # Generate a verification token
            verification_token = str(uuid.uuid4())  # Generate a unique token

            # Insert the new rider into the database
            cursor.execute("""
                INSERT INTO riders (rider_name, rider_email, rider_number, rider_age, rider_address, city,
                    state, account_number, bank_name, guarantor_name, guarantor_number, guarantor_address, 
                    guarantor_relationship, guarantor_occupation, guarantor_state, verification_token, is_verified, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL 1 HOUR))
            """, (form_data['rider_name'], form_data['rider_email'], form_data['rider_number'], form_data['rider_age'], 
                  form_data['residential_address'], form_data['rider_city'], form_data['rider_state'], form_data['acct_num'], 
                  form_data['bank_name'], form_data['guarantor_name'], form_data['guarantor_number'], form_data['guarantor_residential_address'], 
                  form_data['guarantor_relationship'], form_data['guarantor_occupation'], form_data['guarantor_state'], 
                  verification_token, False))  # Set is_verified to False initially
            rd_id = cursor.lastrowid  # Get the auto-incremented ID
            
            # Step 2: Generate user_id in the format CU-xxx
            # rider_id = f"RD-{rd_id:03}"
            rider_id = f"{rd_id}"

            # Step 3: Update the customer record with the generated user_id
            cursor.execute("UPDATE riders SET rider_id = %s WHERE id = %s", (rider_id, rd_id))
            
            """ cursor.execute(""
                INSERT INTO riders (rider_id, rider_name, rider_email, rider_number, password_hash)
                VALUES (%s, %s, %s, %s, %s)
            "", (rider_id, form_data['rider_name'], form_data['rider_email'], form_data['rider_number'], "None")) """

            # Commit the transaction
            connection.commit()

            # create verification link
            verification_link = f"{request.url_root}/verify_rider/{verification_token}"
            body = f"Hi {form_data['rider_name']},\n\nPlease complete your registration and verify your email address by clicking the link below:\n{verification_link}\nThis link will expire in 1 hour.\n\nThank you for accepting to be our rider, Stallion Routes!"

            # Prepare the mail
            msg = EmailMessage()
            msg['Subject'] = 'Verify Your Email - Stallion Routes'
            msg['From'] = EMAIL_USER
            msg['To'] = form_data['rider_email']
            msg.set_content(body)

            # Send the email
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(EMAIL_USER, EMAIL_PASSWORD)
                smtp.send_message(msg)

            # Emit a notification for new rider registration
            socketio.emit('new_rider', {'message': 'A new rider has been registered!'})
            flash("Registration successful! \nProceed to your mail to complete registartion", "success")
            
            # Redirect to clear form fields
            return redirect(url_for('admin_rider'))
        
        finally:
            # Ensure the database connection is closed
            cursor.close()
            connection.close()

    return render_template('admin_rider.html', form_data={}, table_data=table_data, 
            rider_data=rider_data, current_date=current_date, current_time=current_time)

@app.route('/verify_rider/<token>')
def verify_rider_email(token):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT rider_id FROM riders WHERE verification_token = %s AND is_verified = %s AND expires_at > NOW()", (token, False))
        rider = cursor.fetchone()

        if rider:
            # Mark the user as verified
            cursor.execute("UPDATE riders SET is_verified = %s WHERE id = %s", (True, rider[0]))
            connection.commit()
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('rider_signup'))
        else:
            flash('Invalid or expired verification link.', 'danger')
            return redirect(url_for('rider_signup'))
    finally:
        cursor.close()
        connection.close()

@app.route('/resend_rider_verification', methods=['POST'])
def resend_rider_verification():
    if request.method == 'POST':
        email = session['rider_email']  # Get the email from the session
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM riders WHERE rider_email = %s", (email,))
            rider = cursor.fetchone()

            if rider and not rider['is_verified']:  # Check if the user is not verified
                verification_token = str(uuid.uuid4())
                cursor.execute("UPDATE riders SET verification_token = %s, expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE rider_email = %s", (verification_token, email))
                connection.commit()

                # Create the verification link
                verification_url = f"{request.url_root}/verify_rider/{verification_token}"
                body = f"Hi,\n\nPlease verify your email address by clicking the link below:\n{verification_url}\nThis link will expire in 1 hour.\n\nThank you!"
                
                # Prepare the email
                msg = EmailMessage()
                msg['Subject'] = 'Resend Verification - Stallion Routes'
                msg['From'] = EMAIL_USER
                msg['To'] = email
                msg.set_content(body)

                # Send the email
                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                    smtp.login(EMAIL_USER, EMAIL_PASSWORD)
                    smtp.send_message(msg)

                flash('Verification link resent! Please check your email.', 'info')
            else:
                flash('Email not found or already verified.', 'danger')
        except Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            connection.close()
    return redirect(url_for('rider_settings'))

@app.route('/delete_rider/<int:rider_id>', methods=['POST'])
def delete_rider(rider_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Delete the rider from the database
        cursor.execute("DELETE FROM riders WHERE id = %s", (rider_id,))
        connection.commit()
        flash("Rider deleted successfully!", "success")
    except Exception as e:
        connection.rollback()
        flash(f"Error deleting rider: {str(e)}", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('admin_rider'))

@app.route('/admin_rider/<int:rider_id>', methods=['GET', 'POST'])
def edit_rider(rider_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Retrieve the rider's details
    cursor.execute("SELECT * FROM riders WHERE id = %s", (rider_id,))
    rider_data = cursor.fetchone()

    if request.method == 'POST':
        # Update the rider's details
        form_data = {
            'rider_name': request.form['rider_name'],
            'rider_email': request.form['rider_email'],
            'rider_number': request.form['rider_number'],
            'rider_age': request.form['rider_age'],
            'residential_address': request.form['residential_address'],
            'rider_city': request.form['rider_city'],
            'rider_state': request.form['rider_state'],
            'acct_num': request.form['acct_num'],
            'bank_name': request.form['bank_name'],
            'guarantor_name': request.form['guarantor_name'],
            'guarantor_number': request.form['guarantor_number'],
            'guarantor_residential_address': request.form['guarantor_residential_address'],
            'guarantor_relationship': request.form['guarantor_relationship'],
            'guarantor_occupation': request.form['guarantor_occupation'],
            'guarantor_state': request.form['guarantor_state']
        }

        cursor.execute("""
            UPDATE riders SET rider_name = %s, rider_email = %s, rider_number = %s, 
                rider_age = %s, rider_address = %s, city = %s, state = %s, 
                account_number = %s, bank_name = %s, guarantor_name = %s, 
                guarantor_number = %s, guarantor_address = %s, 
                guarantor_relationship = %s, guarantor_occupation = %s, 
                guarantor_state = %s WHERE id = %s
        """, (form_data['rider_name'], form_data['rider_email'], form_data['rider_number'], 
              form_data['rider_age'], form_data['residential_address'], form_data['rider_city'], 
              form_data['rider_state'], form_data['acct_num'], form_data['bank_name'], 
              form_data['guarantor_name'], form_data['guarantor_number'], 
              form_data['guarantor_residential_address'], form_data['guarantor_relationship'],
              form_data['guarantor_occupation'], form_data['guarantor_state'], rider_id))
        connection.commit()
        flash("Rider details updated successfully!", "success")
        return redirect(url_for('admin_rider'))
    else:
        # Render the edit form with the existing rider data
        return render_template('edit_rider.html', rider_data=rider_data)

@app.route('/admin_customer')
def admin_customer():
    # Get current date and time
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, name, email, phone, is_verified
        FROM users
    """)
    customer_data = cursor.fetchall()

    return render_template('admin_customer.html', current_date=current_date, current_time=current_time, customer_data=customer_data)

@app.route('/transaction_history')
def transaction_history():
    return render_template('transaction_history.html')

# Dictionary to store live locations for requests
# rider_locations = {}
rider_locations = defaultdict(list)

@socketio.on('update_rider_location')
def handle_rider_location(data):
    request_id = data['request_id']
    lat = data['lat']
    lng = data['lng']

    # Store the latest rider location in the dictionary
    rider_locations[request_id].append((lat, lng))
    # rider_locations[request_id] = {'lat': lat, 'lng': lng}

    # Emit the new location to the correct customer (based on request_id)
    emit('update_customer_map', {
        'request_id': request_id,
        'lat': lat,
        'lng': lng,
        'path': rider_locations[request_id]
    }, room=request_id)

@socketio.on('join_rider_room')
def join_rider_room(data):
    request_id = str(data['request_id'])
    join_room(request_id)
    print(f"User joined room: {request_id}")

if __name__ == '__main__':
    # app.run(debug=True)
    socketio.run(app, debug=True)  # Run the app with SocketIO