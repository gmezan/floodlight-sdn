package net.floodlightcontroller.internalsecurity;

import org.projectfloodlight.openflow.types.MacAddress;

public class PortScanSuspect {
    private MacAddress sourceMACAddress;
    private MacAddress destMACAddress;
    private Integer ackCounter;
    private Integer synAckCounter;
    private long startTime;



    public MacAddress getSourceMACAddress() {
        return sourceMACAddress;
    }

    public void setSourceMACAddress(MacAddress sourceMACAddress) {
        this.sourceMACAddress = sourceMACAddress;
    }

    public MacAddress getDestMACAddress() {
        return destMACAddress;
    }

    public void setDestMACAddress(MacAddress destMACAddress) {
        this.destMACAddress = destMACAddress;
    }

    public Integer getAckCounter() {
        return ackCounter;
    }

    public void setAckCounter(Integer ackCounter) {
        this.ackCounter = ackCounter;
    }

    public Integer getSynAckCounter() {
        return synAckCounter;
    }

    public void setSynAckCounter(Integer synAckCounter) {
        this.synAckCounter = synAckCounter;
    }

    public long getStartTime() {
        return startTime;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }
}
