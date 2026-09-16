FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV LINJIAN_HOST=0.0.0.0

CMD ["python", "linjian_server.py"]
