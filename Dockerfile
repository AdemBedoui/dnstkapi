# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables for non-interactive apt installation
ENV DEBIAN_FRONTEND=noninteractive

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Install gunicorn (WSGI server for production)
RUN pip install gunicorn

# Expose port 5000 for the app to run on
EXPOSE 5000

# Use gunicorn to run the Flask app with 4 worker threads
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
