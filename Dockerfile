# syntax=docker/dockerfile:1.4
FROM python:3.10-bullseye

WORKDIR /flask
COPY requirements.txt /flask
RUN apt-get update

RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r requirements.txt

COPY . .

ENV FLASK_APP main.py
ENV FLASK_ENV production
ENV FLASK_RUN_PORT 5000
ENV FLASK_RUN_HOST 0.0.0.0
ENV VIRTUAL_HOST cozyinn.tk
ENV LETSENCRYPT_HOST cozyinn.tk
ENV VIRTUAL_PORT 5000
ENV LETSENCRYPT_EMAIL noreply.cozyinn@gmail.com

EXPOSE 5000

CMD ["flask", "run"]