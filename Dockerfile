FROM python:3.10-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]

# This Dockerfile sets up a Python environment using the official Python 3.10 slim image.
# It copies the current directory contents into the /app directory in the container,