package net.floodlightcontroller.useraccesscontrol.entity;

public class Server {
    private int idserver;
    private String name;
    private String ip;
    private String mac;



    public int getIdserver() {
        return idserver;
    }

    public void setIdserver(int idserver) {
        this.idserver = idserver;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }
}
