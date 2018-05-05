FROM alpine:3.7

RUN apk --no-cache add ca-certificates

COPY nomad-exporter /
 
ENTRYPOINT [ "/nomad-exporter" ]
