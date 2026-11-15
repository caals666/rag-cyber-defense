# The website is plain files, so nginx just serves them. No build step, no npm.
FROM nginx:alpine
COPY . /usr/share/nginx/html
# Writes API_URL into config.js every time the container starts (nginx runs scripts in this folder)
COPY 40-api-url.sh /docker-entrypoint.d/40-api-url.sh
RUN chmod +x /docker-entrypoint.d/40-api-url.sh \
 && rm /usr/share/nginx/html/Dockerfile /usr/share/nginx/html/40-api-url.sh /usr/share/nginx/html/.dockerignore
