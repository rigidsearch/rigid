FROM python:3.11-slim-bookworm


RUN useradd -m app
COPY requirements.txt /app/
RUN pip3 install -r /app/requirements.txt
COPY templates /app/templates
COPY static /app/static
COPY app.py /app/
USER app

EXPOSE 5000
ENTRYPOINT python3 /app/app.py