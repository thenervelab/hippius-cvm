# Hippius Sentinel — read-only LLM observability + security agent (§S,
# issue #57). PR-S1 ships only the skeleton image.
#
# Built for linux/amd64 to match the RKE2 cluster (`docker buildx
# build --platform linux/amd64 -t <YOUR_REGISTRY>/hippius-sentinel ...`).
FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Sentinel runs as a non-root, non-privileged user. There is no
# write-back path inside the container (audit anchors land in S3 in
# PR-S2 via outbound HTTPS — never on the local filesystem) so a
# read-only root filesystem is fine.
RUN groupadd --system --gid 10001 sentinel \
    && useradd --system --uid 10001 --gid 10001 --home /home/sentinel --create-home sentinel

WORKDIR /app

# Install the package first as its own layer for cache friendliness.
COPY pyproject.toml ./
COPY sentinel ./sentinel
RUN pip install . \
    && rm -rf /root/.cache/pip

USER sentinel

# k8s liveness probe target (see deploy/kustomize/base/sentinel/deployment.yaml).
EXPOSE 8080

ENTRYPOINT ["hippius-sentinel"]
