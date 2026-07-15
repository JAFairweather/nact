# Nact runtime image. Build context is the nact repo root.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
ENV NACT_PORT=8791
EXPOSE 8791
CMD ["node", "server/server.mjs"]
