# Use Alpine 3.x stable (floating minor) for flexibility
FROM alpine:3

# Optional build arguments
ARG CACHEBUST=1
ARG VERSION

# Metadata labels
LABEL org.opencontainers.image.title="SquidProxy"
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.description="Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/lferrarotti74/SquidProxy"

# Install Squid
# - If VERSION is empty, fallback to latest available in the repo
RUN apk --no-cache update && apk --no-cache upgrade \
    && if [ -z "$VERSION" ]; then \
         echo "⚡ Installing latest Squid available"; \
         apk --no-cache add squid; \
       else \
         echo "⚡ Installing Squid version $VERSION"; \
         apk --no-cache add squid="$VERSION"; \
       fi \
    && apk --no-cache upgrade libssl3 libcrypto3 openssl \
    && rm -rf /var/cache/apk/*

# Copy scripts
COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/healthcheck.sh /healthcheck.sh

RUN chmod 755 /entrypoint.sh /healthcheck.sh

# Copy configuration
COPY config/squid.conf /etc/squid/squid.conf

# Healthcheck
HEALTHCHECK --interval=60s --timeout=5s --retries=3 CMD [ "/healthcheck.sh" ]

# Expose Squid port
EXPOSE 3128/tcp

# Run as Squid user
USER squid

# Entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD []
