#!/bin/bash
# Health check for RBI browser container

# Check Xvfb
if ! pgrep -x "Xvfb" > /dev/null; then
    echo "Xvfb not running"
    exit 1
fi

# Check Chrome is running
if ! pgrep -f "chromium" > /dev/null; then
    echo "Chromium not running"
    exit 1
fi

# Check CDP port is listening
if ! nc -z localhost 9222 2>/dev/null; then
    echo "CDP port not listening"
    exit 1
fi

# Try to get CDP version
RESPONSE=$(curl -s --max-time 2 http://localhost:9222/json/version 2>/dev/null)
if [ -z "$RESPONSE" ]; then
    echo "CDP not responding"
    exit 1
fi

echo "OK"
exit 0
