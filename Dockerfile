FROM python:3.11-slim

WORKDIR /work

RUN apt-get update && apt-get install -y git && apt-get clean

RUN git clone https://github.com/mosquito/pygost.git /tmp/pygost && \
    cd /tmp/pygost && \
    for f in FAQ INSTALL NEWS; do \
        if [ ! -f "$f" ]; then \
            sed -i "/$f/d" setup.py; \
        fi; \
    done && \
    pip install --no-cache-dir asn1crypto /tmp/pygost

COPY sig_verifier.py .
