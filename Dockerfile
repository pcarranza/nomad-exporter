FROM alpine:3.9

RUN apk --no-cache add ca-certificates=20190108-r0

EXPOSE 9441

COPY nomad-exporter /
COPY entrypoint.sh /bin

ENTRYPOINT [ "/bin/entrypoint.sh" ]