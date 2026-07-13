# Node 24 LTS: node:sqlite is stable-unflagged here (it needs --experimental-sqlite on 22.x)
FROM node:24-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src

ENV NODE_ENV=production
# Persist the SQLite db on a mounted volume (Railway: mount a volume at /data)
ENV DATA_DIR=/data

EXPOSE 3000
CMD ["node", "src/index.js"]
