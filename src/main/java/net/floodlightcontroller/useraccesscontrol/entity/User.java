package net.floodlightcontroller.useraccesscontrol.entity;

import java.time.LocalDateTime;

public class User {

    private String fullname;
    private int idrol;
    private boolean active;
    private LocalDateTime active_timestamp;
    private String ip;
    private String mac;
    private String attachment_point;


    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

    public int getIdrol() {
        return idrol;
    }

    public void setIdrol(int idrol) {
        this.idrol = idrol;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public LocalDateTime getActive_timestamp() {
        return active_timestamp;
    }

    public void setActive_timestamp(LocalDateTime active_timestamp) {
        this.active_timestamp = active_timestamp;
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

    public String getAttachment_point() {
        return attachment_point;
    }

    public void setAttachment_point(String attachment_point) {
        this.attachment_point = attachment_point;
    }
}
