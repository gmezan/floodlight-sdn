FROM java:8
WORKDIR /floodlight/
ADD ./ /floodlight/
EXPOSE 8080
CMD java -jar target/floodlight.jar

