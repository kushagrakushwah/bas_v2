FROM python:3.10-slim

WORKDIR /app

# System deps

RUN apt-get update && apt-get install -y 
gcc 
build-essential 
curl 
&& rm -rf /var/lib/apt/lists/*

# Install Python deps

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ENTIRE dashboard

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
