FROM alpine:latest

RUN apk add --no-cache squid

COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/healthcheck.sh /healthcheck.sh
RUN chmod 755 /entrypoint.sh
RUN chmod 755 /healthcheck.sh

COPY config/squid.conf /etc/squid/squid.conf

# Define a custom healthcheck command
HEALTHCHECK --interval=60s --timeout=5s --retries=3 CMD [ "/healthcheck.sh" ]

EXPOSE 3128/tcp
USER squid

CMD []
ENTRYPOINT ["/entrypoint.sh"]