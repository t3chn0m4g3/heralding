# syntax=docker/dockerfile:1
# Heralding 2.0 – credentials catching honeypot
# Build: docker build -t heralding .
# Run:   docker run --read-only --tmpfs /tmp/heralding:uid=2000,gid=2000 \
#          -v "$PWD/log:/var/log/heralding" -p 21:21 -p 22:22 ... heralding

FROM python:3.14-alpine@sha256:2e740b2c28a426e74f11396c05e38afb3191acced75045b8d62df573c1dc8ce8 AS build
COPY --from=ghcr.io/astral-sh/uv:0.12@sha256:f513a91fc62fe7c17567eee97230dd198e43edb8a9fbecca843714a4358fe1bc /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /opt/heralding
# dependencies first (cached layer), then the project itself
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY heralding ./heralding
RUN uv sync --locked --no-dev --no-editable

FROM python:3.14-alpine@sha256:2e740b2c28a426e74f11396c05e38afb3191acced75045b8d62df573c1dc8ce8
RUN apk --no-cache add libcap \
    && addgroup -g 2000 heralding \
    && adduser -S -H -s /sbin/nologin -u 2000 -G heralding heralding \
    && mkdir -p /etc/heralding /var/log/heralding /tmp/heralding \
    && chown heralding:heralding /var/log/heralding /tmp/heralding
COPY --from=build /opt/heralding /opt/heralding
COPY heralding/heralding.yml /etc/heralding/heralding.yml
# in the container the activity logs belong on the log volume, not in the tmpfs work dir
RUN sed -i -E 's#_log_file: "(log_[a-z_]+\.(csv|json))"#_log_file: "/var/log/heralding/\1"#' \
        /etc/heralding/heralding.yml \
    && sed -i 's#/var/log/heralding/log_auth.csv#/var/log/heralding/auth.csv#' /etc/heralding/heralding.yml
# bind ports < 1024 without root; the venv's python links to the system binary
RUN setcap cap_net_bind_service=+ep "$(readlink -f /opt/heralding/.venv/bin/python)" \
    && apk del libcap
ENV PATH=/opt/heralding/.venv/bin:$PATH

EXPOSE 21 22 23 25 80 110 143 389 443 445 465 587 636 990 993 995 1080 1433 1883 \
       3306 3389 5060 5060/udp 5432 5900 6379 8080 8883

STOPSIGNAL SIGINT
WORKDIR /tmp/heralding
USER heralding:heralding
CMD ["heralding", "-c", "/etc/heralding/heralding.yml", "-l", "/var/log/heralding/heralding.log"]
