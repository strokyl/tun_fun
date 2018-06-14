FROM alpine:3.7
RUN apk --no-cache add docker bash netcat-openbsd
COPY test.sh /bin/test.sh
ENTRYPOINT ["/bin/test.sh"]
