FROM ghcr.io/puppeteer/puppeteer:23.11.0

ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable \
    NODE_ENV=production \
    PORT=10000

WORKDIR /home/pptruser/app

COPY --chown=pptruser:pptruser package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY --chown=pptruser:pptruser server.js ./

EXPOSE 10000

CMD ["node", "server.js"]
