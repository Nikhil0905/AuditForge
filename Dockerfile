FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN pip install --upgrade pip && pip install -r requirements.txt
CMD ["python3", "AuditForge/src/main.py"] 