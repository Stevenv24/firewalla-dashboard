# Claude worker: Python and Anthropic's own Python library (pinned), nothing
# else. The script (worker.py) is mounted from the project folder by
# compose.yaml, so changing it needs only a restart; changing this file
# needs Project Stop + Build in Container Manager.
# Python 3.12 on Debian 13 (trixie), like the dashboard: a Build gets
# Debian security fixes, never a new Python or Debian release by surprise.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /worker
CMD ["python", "/worker/worker.py"]
