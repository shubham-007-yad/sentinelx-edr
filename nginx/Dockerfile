FROM nginx:alpine

# Create certs directory inside container
RUN mkdir -p /etc/nginx/certs

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy self-signed default certificates into image
COPY certs/ /etc/nginx/certs/

EXPOSE 80 443

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
  CMD wget --no-verbose --spider --no-check-certificate https://localhost/healthz || wget --no-verbose --spider http://localhost/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
