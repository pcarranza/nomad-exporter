FROM alpine:3.8

RUN apk --no-cache add ca-certificates=20190108-r0

EXPOSE 9441

COPY nomad-exporter /
 
ENTRYPOINT [ "/nomad-exporter" ]
