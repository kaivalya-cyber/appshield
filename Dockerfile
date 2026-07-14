# ─── Build stage ────────────────────────────────────────────────────────────
FROM node:26-alpine AS builder

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# Copy source and build
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ─── Production stage ───────────────────────────────────────────────────────
FROM node:26-alpine

WORKDIR /app

# Copy only production deps and built output
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY --from=builder /app/dist ./dist

# Add .env support hint
RUN echo 'ANTHROPIC_API_KEY=your_key_here' > .env.example

# Set up entrypoint
ENTRYPOINT ["node", "dist/index.js"]

# Default command
CMD ["--help"]

LABEL org.opencontainers.image.title="AppShield"
LABEL org.opencontainers.image.description="AI-powered security scanner CLI that uses Claude to find vulnerabilities in your code"
LABEL org.opencontainers.image.url="https://github.com/yourusername/appshield"
LABEL org.opencontainers.image.version="1.0.0"
