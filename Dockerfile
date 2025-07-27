# Use a specific, newer Python version
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Make port 8989 available to the world outside this container
EXPOSE 8989

# Define the command to run your app
CMD ["python", "./clab_mcp_server.py"]
