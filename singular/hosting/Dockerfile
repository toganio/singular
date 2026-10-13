# Singular hosted-agent runtime: Hermes Agent + Singular, one agent per container.
#
#   docker build -f singular/hosting/Dockerfile -t singular-runtime .        # from the repository root
#
# The image holds no agent. On first start `singular host` pulls the agent's capsule (an OCI artifact, an
# https URL or a file), verifies it against the ledger, and keeps it in the /agent/home volume; every start
# then takes the run lease, runs Hermes under it, and seals and releases on SIGTERM. Configuration is
# environment only: see singular/src/singular/hosting.py. Singular Cloud runs this exact image; so can you.
#
# Hermes is installed the way its own Dockerfile does it: locked dependencies (`uv sync --frozen`), then an
# editable link to the source at this commit (Hermes refuses to be built as a wheel).
FROM python:3.14-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/hermes/.venv \
    PATH=/opt/hermes/.venv/bin:$PATH

RUN apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends ca-certificates tini git ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.11.6

WORKDIR /opt/hermes
# Dependencies first, so a source-only change does not redo them. The gateway's messaging adapters
# (Telegram, Discord, Slack) and the Anthropic provider are baked in: hosted agents cannot lazy-install.
COPY pyproject.toml uv.lock ./
RUN touch README.md \
    && uv sync --frozen --no-install-project --extra messaging --extra anthropic

COPY . .
RUN uv pip install --no-deps -e . \
    && uv pip install -e ./singular \
    && singular --version

# Group 0 owns the agent's folders, so the image also runs as any uid in group 0 (`--user "$(id -u):0"`):
# that is how a host lets the agent rewrite its package file in a folder the host user owns.
RUN useradd --uid 10001 --gid 0 --create-home --home-dir /agent --shell /usr/sbin/nologin agent \
    && mkdir -p /agent/home && chown -R 10001:0 /agent && chmod -R g=u /agent
USER 10001:0
WORKDIR /agent
VOLUME ["/agent/home"]

# `singular pack` builds agent images on this one and refuses any base without this label.
LABEL dev.singular.runtime="1"
ENV SINGULAR_HOME=/agent/home \
    HERMES_HOME=/agent/home \
    HOME=/agent

ENTRYPOINT ["/usr/bin/tini", "--", "singular", "host"]
