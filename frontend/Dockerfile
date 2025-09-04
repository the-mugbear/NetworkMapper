FROM node:18-alpine

WORKDIR /app

# Install git for version info
RUN apk add --no-cache git

# Copy package files
COPY package*.json ./
COPY generate-build-info.js ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Generate build info
RUN node generate-build-info.js

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]