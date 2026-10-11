FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir cryptography==50.0.2
COPY wire-server.py /app/wire-server.py

ENV WIRE_STATE=/data
EXPOSE 47666/tcp
VOLUME ["/data"]
CMD ["python", "/app/wire-server.py"]
