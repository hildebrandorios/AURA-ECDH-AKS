FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine

WORKDIR /app

# Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# Ensure correct permissions for the non-root user
RUN chown -R appuser:appgroup /app
USER appuser

COPY --from=builder --chown=appuser:appgroup /app/package*.json ./
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
RUN npm ci --omit=dev

EXPOSE 3000

ENV PORT=3000

CMD ["node", "dist/src/server.js"]
