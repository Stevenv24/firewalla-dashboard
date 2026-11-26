# Same base as the dashboard: Python 3.12 on Debian 13 (trixie).
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# overview.py and static/ are mounted read-only by compose.yaml, so changing
# them needs only a restart.
WORKDIR /overview
CMD ["uvicorn", "overview:app", "--host", "0.0.0.0", "--port", "8080"]
