FROM cccs/assemblyline-v4-service-base:stable

ENV SERVICE_PATH cape.Cape

USER root

RUN apt update
RUN pip3 install requests

USER assemblyline

WORKDIR /opt/al_service
COPY . .

ARG version=4.2.0.stable1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
