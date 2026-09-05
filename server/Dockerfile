FROM node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY frontend/package.json frontend/package-lock.json* ./frontend/
RUN npm install --prefix frontend
COPY . .
RUN npm run build

FROM node:26-alpine AS runtime
WORKDIR /app
# pg_dump/psql for the dashboard's backup and restore actions (see
# src/backup/). Pinned to the same major version as the postgres:16-alpine
# server in docker-compose.yml - pg_dump refuses to dump a server newer
# than itself, so these two move together. ~3 MB.
RUN apk add --no-cache postgresql16-client
ENV NODE_ENV=production
# Node's fetch (undici) ignores HTTP_PROXY/HTTPS_PROXY/NO_PROXY unless this
# is set, which is how the NVD, EPSS, KEV and GitHub syncs would silently
# time out in a network that requires a proxy - with nothing in the logs
# pointing at the proxy as the cause. Set unconditionally because it only
# ever means "honour those variables if they are set at all": with none
# set, connections go direct exactly as before (verified, not assumed).
ENV NODE_USE_ENV_PROXY=1
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist
COPY --from=build /app/frontend/dist ./frontend/dist
COPY migrations ./migrations
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["./docker-entrypoint.sh"]
