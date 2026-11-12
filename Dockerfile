# hm360 dashboard in one container. The Windows collector runs on each PC as a scheduled task (a Linux container
# can't read Windows health), and drops its envelope into the mounted inbox.
FROM node:22-bookworm-slim
ENV NODE_ENV=production PORT=3460 HM360_BIND=0.0.0.0 HM360_DATA=/data
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server ./server
COPY public ./public
RUN mkdir -p /data/inbox /data/feeds && chown -R node:node /data
USER node
EXPOSE 3460
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:3460/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/index.mjs"]
