# Official Puppeteer image includes Chrome and its system libraries.
FROM ghcr.io/puppeteer/puppeteer:23.11.0

ENV PUPPETEER_SKIP_DOWNLOAD=true \
    NODE_ENV=production

WORKDIR /home/pptruser/app

COPY --chown=pptruser:pptruser package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY --chown=pptruser:pptruser server.js ./

# Platforms set PORT; default matches server.js.
ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.js"]
