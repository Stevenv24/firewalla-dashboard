# Python 3.12 on Debian 13 (trixie): a Build gets Python 3.12 and Debian
# security fixes, never a new Python or Debian release by surprise.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

# For the guided setup's one password login to the router (setup.py): ssh
# never reads a password from a pipe, so it asks this program, which prints
# the password setup handed to that one ssh run and nothing else. It lives
# in the image because /tmp can't run programs.
RUN printf '#!/bin/sh\nprintf "%%s\\n" "$DASHBOARD_SETUP_PASSWORD"\n' > /usr/local/bin/dashboard-askpass \
    && chmod 755 /usr/local/bin/dashboard-askpass

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt

RUN pip install \
    --no-cache-dir \
    -r /tmp/requirements.txt

COPY app/ /app/

# start-dashboard.sh is not built in: compose.yaml mounts it from the NAS
# folder at /start-dashboard.sh and runs it, so changes to it need only
# a container restart. Keep it saved with Unix (LF) line endings.
CMD ["/bin/sh", "/start-dashboard.sh"]