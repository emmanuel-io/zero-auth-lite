FROM node:22-alpine

RUN npm install --global --omit=dev lcoview@1.1.1 \
    && npm cache clean --force

ENTRYPOINT ["lcoview"]
