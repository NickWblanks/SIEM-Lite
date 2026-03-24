FROM python:3.12

WORKDIR /app

COPY Log_Generator.py .

CMD ["python", "Log_Generator.py"]

