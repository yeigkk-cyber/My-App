FROM python:3.12-slim
WORKDIR /app
COPY server.py index.html ./
ENV FABRIC_DATA_DIR=/var/data
EXPOSE 10000
CMD ["python", "server.py"]
