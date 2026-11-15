#!/bin/sh
# Points the website at the backend: API_URL comes from docker-compose.yml
if [ -n "$API_URL" ]; then
  echo "window.API_URL = \"$API_URL\";" > /usr/share/nginx/html/config.js
fi
