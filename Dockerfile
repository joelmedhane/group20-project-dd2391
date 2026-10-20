FROM node:20-slim

WORKDIR /app

COPY vulnerable-sqli-demoAI/package*.json ./

RUN npm ci

COPY vulnerable-sqli-demoAI/ .

EXPOSE 3000

CMD ["npm", "start"]