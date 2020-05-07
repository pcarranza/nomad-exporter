FROM alpine:3.9

RUN apk --no-cache add ca-certificates

EXPOSE 9441

COPY nomad-exporter /
 
ENTRYPOINT [ "/nomad-exporter" ]
