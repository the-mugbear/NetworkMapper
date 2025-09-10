# Build stage
FROM node:18-alpine as builder

WORKDIR /app

# Install git for version info
RUN apk add --no-cache git

# Copy package files for dependency caching
COPY package*.json ./
COPY generate-build-info.js ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci --silent \
    && npm cache clean --force

# Cache-busting argument
ARG CACHE_BUST=default_value

# Use cache-bust to invalidate layers for source code
RUN echo "Cache bust: $CACHE_BUST" > /tmp/cache_bust.txt

# Copy source code (cache-busted)
COPY . .

# Generate build info and build the application
RUN node generate-build-info.js \
    && npm run build \
    && npm prune --production

# Production stage
FROM nginx:alpine as production

# Install security updates and curl for health check
RUN apk upgrade --no-cache \
    && apk add --no-cache curl

# Copy build files and nginx configuration
COPY --from=builder /app/build /usr/share/nginx/html
COPY --from=builder /app/nginx.conf /etc/nginx/conf.d/default.conf

# Remove default nginx configuration
RUN rm -f /etc/nginx/conf.d/default.conf.bak || true

# Ensure proper permissions for nginx
RUN chmod -R 755 /usr/share/nginx/html

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]