FROM python:3.13-slim

WORKDIR /app

# Install system utilities, git, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep CLI
RUN pip install --no-cache-dir semgrep

# Install Gitleaks binary
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks

# Install Trivy binary
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt asyncpg

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]