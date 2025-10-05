FROM alpine:3

# Define an optional build argument to invalidate cache
ARG CACHEBUST=1

ARG VERSION

LABEL org.opencontainers.image.title="SquidProxy"
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.description="Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/lferrarotti74/SquidProxy"

RUN apk --no-cache update && apk --no-cache upgrade \
    && apk --update --no-cache add squid=${VERSION} \
    && apk --no-cache upgrade libssl3 libcrypto3 openssl \
    && rm -rf /var/cache/apk/*

COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/healthcheck.sh /healthcheck.sh

RUN chmod 755 /entrypoint.sh ; chmod 755 /healthcheck.sh

# Copy local files to base image
COPY config/squid.conf /etc/squid/squid.conf

# Define a custom healthcheck command
HEALTHCHECK --interval=60s --timeout=5s --retries=3 CMD [ "/healthcheck.sh" ]

EXPOSE 3128/tcp
USER squid

CMD []
ENTRYPOINT ["/entrypoint.sh"]
