ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANSIBLE_HOST_KEY_CHECKING=False \
    ANSIBLE_RETRY_FILES_ENABLED=False \
    EDITOR=vi \
    VISUAL=vi

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client sshpass ca-certificates vim-tiny iputils-ping iproute2 netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY playbooks ./playbooks

CMD ["python", "-m", "app.scheduler"]
