package net.floodlightcontroller.mactracker;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=MACTrackerDtoSerializer.class)
public class MACTrackerDto {
    private String macAddress;
    private String attachmentPoint;

    public MACTrackerDto(){}

    public MACTrackerDto(String macAddress, String attachmentPoint){
        this.macAddress = macAddress;
        this.attachmentPoint = attachmentPoint;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public String getAttachmentPoint() {
        return attachmentPoint;
    }

    public void setAttachmentPoint(String attachmentPoint) {
        this.attachmentPoint = attachmentPoint;
    }
}
