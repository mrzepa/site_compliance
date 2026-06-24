ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY config ./config
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "vet_compliance.cli", "--config", "config/config.yaml", "--rules", "config/compliance.yaml"]
