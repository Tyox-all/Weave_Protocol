# Mund - The Guardian Protocol
# Docker image for running Mund MCP server

FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built files
COPY dist/ ./dist/
COPY rules/ ./rules/

# Create non-root user
RUN addgroup -g 1001 -S mund && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G mund -g mund mund

# Set ownership
RUN chown -R mund:mund /app

# Switch to non-root user
USER mund

# Default environment variables
ENV MUND_PORT=3000
ENV MUND_HOST=0.0.0.0
ENV MUND_TRANSPORT=http
ENV MUND_STORAGE=memory
ENV MUND_BLOCK_MODE=alert
ENV MUND_LOG_LEVEL=info

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Run server
CMD ["node", "dist/index.js"]
