# Use an official Python image as the base
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the receiver code into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the receiver listens on
EXPOSE 5000

# Command to run the receiver
CMD ["python3", "receiver.py"]