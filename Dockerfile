FROM python:3.5-alpine

RUN pip install prometheus_client requests

ENV BIND_PORT 9188

ADD src /app
WORKDIR /app

CMD ["python", "ssl_exporter.py"]
