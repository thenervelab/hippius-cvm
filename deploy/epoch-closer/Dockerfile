# §23 periodic epoch-close worker — node + @polkadot/api.
FROM mirror.gcr.io/library/node:22.23.4-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d
# Links the GHCR package to this repo so the `epoch-closer-image`
# workflow's GITHUB_TOKEN can push + cosign-sign it (RA-N7). Every other
# hippius image is repo-linked; this one was pushed off-CI and orphaned.
LABEL org.opencontainers.image.source="https://github.com/thenervelab/hippius-compute"
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY close-epoch.mjs apply-prices.mjs ./
USER node
ENTRYPOINT ["node", "close-epoch.mjs"]
