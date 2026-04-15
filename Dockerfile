FROM python:3.11-slim

WORKDIR /app
COPY app.py index.html style.css ./

RUN pip install --no-cache-dir flask pillow

EXPOSE 5000
CMD ["python", "app.py"]
