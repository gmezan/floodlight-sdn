package net.floodlightcontroller.internalsecurity;

public class Data {
    private Integer synCounter;
    private Integer synAckCounter;
    private long startTime;


    public Integer getSynCounter() {
        return synCounter;
    }

    public void setSynCounter(Integer synCounter) {
        this.synCounter = synCounter;
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
