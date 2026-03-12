# ===================== Stage 1: PD Tools =====================
FROM golang:1.22-alpine AS pd-tools
RUN apk add --no-cache git

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ===================== Stage 2: Python Deps =====================
FROM python:3.11-slim AS deps
WORKDIR /app
COPY requirements.txt ./
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y gcc libffi-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# ===================== Stage 3: Production =====================
FROM python:3.11-slim AS runner
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        dnsrecon \
        libcairo2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 \
        fonts-noto-cjk \
        curl \
        && rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/drwetter/testssl.sh/archive/refs/heads/3.2/main.tar.gz | \
    tar xz -C /opt/ && \
    ln -s /opt/testssl.sh-3.2-main/testssl.sh /usr/local/bin/testssl.sh

COPY --from=pd-tools /root/go/bin/subfinder /usr/local/bin/
COPY --from=pd-tools /root/go/bin/httpx /usr/local/bin/
COPY --from=pd-tools /root/go/bin/nuclei /usr/local/bin/
COPY --from=pd-tools /root/go/bin/dnsx /usr/local/bin/
COPY --from=pd-tools /root/go/bin/naabu /usr/local/bin/

COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

RUN groupadd -r cypulse && useradd -r -g cypulse cypulse && \
    mkdir -p /app/data /app/config && \
    chown -R cypulse:cypulse /app

COPY --chown=cypulse:cypulse . .

USER cypulse

ENTRYPOINT ["python", "-m", "cypulse"]
CMD ["--help"]
