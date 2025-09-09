FROM node:18-alpine

WORKDIR /app

# Install git for version info
RUN apk add --no-cache git

# Cache-busting argument
ARG CACHE_BUST=default_value

# Copy package files
COPY package*.json ./
COPY generate-build-info.js ./

# Install dependencies
RUN npm install

# Use cache-bust to invalidate layers
RUN echo "Cache bust: $CACHE_BUST" > /tmp/cache_bust.txt

# Copy source code (cache-busted)
COPY . .

# Generate build info
RUN node generate-build-info.js

# Expose port
EXPOSE 3000

# Clear any cached builds and node modules
RUN rm -rf node_modules/.cache || true
RUN rm -rf build || true

# Build the application for production
RUN npm run build

# Install serve to serve the production build
RUN npm install -g serve

# Start the application in production mode
CMD ["serve", "-s", "build", "-l", "3000"]