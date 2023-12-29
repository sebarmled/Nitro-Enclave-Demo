FROM python:3.10-slim

LABEL maintainer="cj.christopherjude@gmail.com"

ARG REGION
ARG SECRET

ENV ENVIRONMENT prod

ENV REGION=$REGION
ENV SECRET=$SECRET

ENV LD_LIBRARY_PATH /enclave/kms/

WORKDIR /enclave

COPY enclave/ /enclave

RUN apt-get update && \
    apt-get install -y build-essential && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 5010

CMD ["/usr/local/bin/python3", "/enclave/enclave.py"]

