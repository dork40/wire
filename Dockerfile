FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir cryptography==50.0.2
COPY wire-server.py /app/wire-server.py
COPY wire-web.py /app/wire-web.py

ENV WIRE_STATE=/data
EXPOSE 47666/tcp 8097/tcp
VOLUME ["/data"]
CMD ["python", "/app/wire-server.py"]
