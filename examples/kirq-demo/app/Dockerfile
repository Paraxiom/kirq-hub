# Start from the latest Ubuntu image
FROM ubuntu:latest

# Update, install system dependencies and upgrade system packages
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
    build-essential git cmake libssl-dev python3 python3-venv python3-pip curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Get and build liboqs
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs && \
    cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 4 && \
    cmake --build liboqs/build --target install

# Add a normal user
RUN useradd -m -c "Open Quantum Safe" oqs
USER oqs
WORKDIR /home/oqs

# Create and activate a Python 3 virtual environment
RUN python3 -m venv venv
ENV PATH="/home/oqs/venv/bin:$PATH"

# Get and install liboqs-python
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs-python.git
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
ENV PYTHONPATH=$PYTHONPATH:/home/oqs/liboqs-python

# Activate the virtual environment and install liboqs-python
RUN . venv/bin/activate && cd liboqs-python && pip install . && cd $HOME

# Switch to the root user to copy the application files and install app dependencies
USER root

# Set the working directory in the container
WORKDIR /app

# Copy the application certificate
COPY certificate/ ./certificate

# Copy the application source code
COPY src/ ./src

# Copy the data directory into the container
COPY data/ ./data

# Copy the ETSI014 directory into the container
COPY ETSI014/ ./ETSI014

COPY src/requirements.txt ./requirements.txt

# Set the environment variable for Streamlit configuration
ENV DATA_DIR=/app/data

# Install the required Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8501 available to the world outside this container
EXPOSE 8501

# Health check for Streamlit server
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Run the Streamlit application
CMD ["streamlit", "run", "./src/app.py", "--server.port=8501", "--server.address=0.0.0.0"]

## To build :
# > cd path/to/code/demo
# > docker build -f app/Dockerfile -t kirq-demo .

## To run :
# > docker run -p 8501:8501 kirq-demo
# Visit http://localhost:8501 to use the app

## Interactive Shell session
# docker run --rm -it kirq-demo:latest /bin/bash

# Made with ♥ by Emmanuel Calvet, system's architect from Numana (2024)
