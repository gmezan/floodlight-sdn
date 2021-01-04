FROM openjdk:8-jre-alpine
WORKDIR /floodlight-sdn/
COPY ./ /floodlight-sdn/
CMD ["/usr/bin/java", "-jar", "target/floodlight.jar"]


