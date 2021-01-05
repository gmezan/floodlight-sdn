package net.floodlightcontroller.useraccesscontrol.entity;

public class Service {
    private int idservice;
    private String name;
    private int port;
    private String protocol;
    private int idserver;




    public int getIdservice() {
        return idservice;
    }

    public void setIdservice(int idservice) {
        this.idservice = idservice;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public int getIdserver() {
        return idserver;
    }

    public void setIdserver(int idserver) {
        this.idserver = idserver;
    }
}
