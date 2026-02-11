FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built files
COPY dist ./dist

# Expose port
EXPOSE 3001

# Start server
CMD ["node", "dist/index.js"]
