# Use the official Python image as the base
FROM python:3.10-slim

# Install system dependencies (libsqlite3 and liboqs dependencies)
RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    sqlite3 \
    cmake \
    gcc \
    ninja-build \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs
RUN git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cd /tmp/liboqs \
    && mkdir build && cd build \
    && cmake -GNinja -DOQS_ALGS_ENABLED=ML_KEM .. \
    && ninja \
    && ninja install \
    && rm -rf /tmp/liboqs

# Set the working directory
WORKDIR /app

# Copy the application files (including api_keys.db)
COPY . .

# Install Python dependencies (including liboqs-python)
RUN pip install --no-cache-dir -r requirements.txt \
    && ( \
       for i in {1..5}; do \
           git clone https://github.com/open-quantum-safe/liboqs-python.git /tmp/liboqs-python && break || sleep 10; \
       done; \
       if [ -d "/tmp/liboqs-python" ]; then \
           cd /tmp/liboqs-python \
           && pip install . \
           && rm -rf /tmp/liboqs-python; \
       else \
           echo "Failed to clone liboqs-python after 5 attempts" && exit 1; \
       fi \
    )

# Expose the port the app runs on
EXPOSE 8080

# Run the app with waitress on port 8080
CMD ["waitress-serve", "--port=8080", "app:app"]