# HeatMap 360 web app (upload API, results pages, PDF). The bot does NOT run here: it runs on the admin's desktop as a
# GitHub Actions self-hosted runner job in hm-360-data. Settings and the GitHub token come from Container Apps env vars
# and secret refs at run time, never from the image.
FROM node:22-bookworm-slim
ENV NODE_ENV=production PORT=3460 HM360_BIND=0.0.0.0
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server ./server
COPY public ./public
COPY client ./client
USER node
EXPOSE 3460
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:3460/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/index.mjs"]
