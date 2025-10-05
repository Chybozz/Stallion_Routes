from app import app, socketio  # import both from app.py

# Expose app and socketio for Gunicorn
# application = app  # optional, for compatibility
# socketio_app = socketio  # alias, optional

if __name__ == "__main__":
    # Local run
    socketio.run(app, debug=True)
