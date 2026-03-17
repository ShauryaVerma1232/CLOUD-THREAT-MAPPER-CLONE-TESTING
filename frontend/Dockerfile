FROM node:20-alpine

WORKDIR /app

# Copy package files first for layer caching
COPY package*.json ./
RUN npm install

# Source is mounted as a volume in dev
EXPOSE 3000
