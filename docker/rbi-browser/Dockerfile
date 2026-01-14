# OpenSASE RBI Browser Container
# Secure Chromium environment for Remote Browser Isolation

FROM ubuntu:22.04 AS base

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install Chromium and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium-browser \
    chromium-codecs-ffmpeg \
    xvfb \
    x11vnc \
    fluxbox \
    pulseaudio \
    dbus \
    dbus-x11 \
    fonts-liberation \
    fonts-noto-cjk \
    fonts-noto-color-emoji \
    fonts-dejavu \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpulse0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash user \
    && mkdir -p /home/user/.config/chromium \
    && chown -R user:user /home/user

# Chrome managed policies (disable dangerous features)
COPY policies.json /etc/chromium/policies/managed/
RUN chmod 644 /etc/chromium/policies/managed/policies.json

# Install control daemon (from builder stage in production)
# COPY --from=builder /app/rbi-daemon /usr/local/bin/rbi-daemon
# COPY --from=builder /app/pixel-encoder /usr/local/bin/pixel-encoder

# Startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Health check script
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /healthcheck.sh

# Switch to non-root user
USER user
WORKDIR /home/user

# Environment
ENV DISPLAY=:99 \
    DBUS_SESSION_BUS_ADDRESS=/dev/null \
    HOME=/home/user \
    CHROME_FLAGS="--no-sandbox --disable-gpu --disable-dev-shm-usage --disable-extensions --disable-plugins --disable-translate --disable-sync --no-first-run --disable-background-networking"

# Expose ports
# 8080 - Control API
# 9222 - Chrome DevTools Protocol
# 5900 - VNC (internal)
EXPOSE 8080 9222 5900

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/healthcheck.sh"]

CMD ["/start.sh"]
