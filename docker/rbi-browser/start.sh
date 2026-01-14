#!/bin/bash
# RBI Browser Container Startup Script

set -e

echo "Starting OpenSASE RBI Browser Container..."

# Start virtual framebuffer
Xvfb :99 -screen 0 1920x1080x24 -nolisten tcp &
XVFB_PID=$!
sleep 2

# Start window manager (minimal)
fluxbox &
sleep 1

# Start VNC server (internal only)
x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -xkb &
VNC_PID=$!

# Start PulseAudio (for audio streaming if needed)
pulseaudio --start --exit-idle-time=-1 2>/dev/null || true

# Start Chrome with security flags
chromium-browser \
    --remote-debugging-port=9222 \
    --remote-debugging-address=0.0.0.0 \
    --no-sandbox \
    --disable-gpu \
    --disable-dev-shm-usage \
    --disable-extensions \
    --disable-plugins \
    --disable-translate \
    --disable-sync \
    --disable-background-networking \
    --disable-default-apps \
    --disable-client-side-phishing-detection \
    --no-first-run \
    --disable-component-update \
    --disable-hang-monitor \
    --disable-prompt-on-repost \
    --disable-domain-reliability \
    --disable-features=TranslateUI,BlinkGenPropertyTrees \
    --disable-ipc-flooding-protection \
    --password-store=basic \
    --use-mock-keychain \
    --window-size=1920,1080 \
    --window-position=0,0 \
    --start-maximized \
    --kiosk \
    about:blank &
CHROME_PID=$!

echo "Chrome started with PID: $CHROME_PID"
echo "VNC on port 5900, CDP on port 9222"

# Start control API server
# In production: /usr/local/bin/rbi-daemon --port 8080
# For now, simple HTTP health endpoint
while true; do
    echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK" | nc -l -p 8080 -q 1 2>/dev/null || true
done &

# Wait for main process
wait $CHROME_PID
