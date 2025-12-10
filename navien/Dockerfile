FROM python:3.11-slim

WORKDIR /usr/src/app

COPY navien.py .
COPY run.sh .

RUN pip install paho-mqtt

CMD ["/usr/src/app/run.sh"]
