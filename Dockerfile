# ===================== Stage 1: PD Tools =====================
FROM golang:1.24-bookworm AS pd-tools
RUN apt-get update && apt-get install -y --no-install-recommends git libpcap-dev gcc && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto
ENV GOBIN=/usr/local/bin
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN CGO_ENABLED=0 go install -v github.com/owasp-amass/amass/v4/...@latest
# M8 雲端資產暴露模組：s3scanner（sa7mon/S3Scanner）
RUN CGO_ENABLED=0 go install -v github.com/sa7mon/s3scanner@latest

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
        libpcap0.8 \
        libcairo2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        fonts-noto-cjk \
        curl \
        bsdextrautils \
        openssl \
        procps \
        gosu \
        && rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/testssl/testssl.sh/archive/refs/heads/3.2.tar.gz | \
    tar xz -C /opt/ && \
    ln -s /opt/testssl.sh-3.2/testssl.sh /usr/local/bin/testssl.sh

RUN groupadd -r cypulse && useradd -r -g cypulse -m cypulse && \
    mkdir -p /app/data /app/config && \
    chown -R cypulse:cypulse /app

COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

COPY --from=pd-tools /usr/local/bin/subfinder /usr/local/bin/
COPY --from=pd-tools /usr/local/bin/httpx /usr/local/bin/
COPY --from=pd-tools /usr/local/bin/nuclei /usr/local/bin/
COPY --from=pd-tools /usr/local/bin/dnsx /usr/local/bin/
COPY --from=pd-tools /usr/local/bin/naabu /usr/local/bin/
COPY --from=pd-tools /usr/local/bin/amass /usr/local/bin/
COPY --from=pd-tools /usr/local/bin/s3scanner /usr/local/bin/

COPY --chown=cypulse:cypulse . .
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s \
    CMD ["python", "-m", "cypulse", "--help"]

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--help"]
