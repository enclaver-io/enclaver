FROM node:lts-alpine

WORKDIR /usr/src/app

COPY package.json ./
RUN npm install

COPY app.js ./

ENTRYPOINT ["node", "/usr/src/app/app.js"]