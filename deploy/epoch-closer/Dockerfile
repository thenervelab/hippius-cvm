# §23 periodic epoch-close worker — node + @polkadot/api.
FROM node:22-slim@sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4
# Links the GHCR package to this repo so the `epoch-closer-image`
# workflow's GITHUB_TOKEN can push + cosign-sign it (RA-N7). Every other
# hippius image is repo-linked; this one was pushed off-CI and orphaned.
LABEL org.opencontainers.image.source="https://github.com/thenervelab/hippius-compute"
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY close-epoch.mjs ./
USER node
ENTRYPOINT ["node", "close-epoch.mjs"]
