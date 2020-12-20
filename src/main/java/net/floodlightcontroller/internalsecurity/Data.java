package net.floodlightcontroller.internalsecurity;

import java.util.Map;

import org.projectfloodlight.openflow.types.TransportPort;

public class Data {
    private Integer synCounter; // Contador de veces que se ha mandado un SYN
    private Integer synAckCounter; // Contador de veces que se ha respondido el SYN con Ack
    private long startTime;		// Contador de cuando se empezo a evaluar
    private Map<Integer, Integer> portMap; // Mapea protocolos con contador: e.g. <SSH, 2> <ICMP, 100>


    public Map<Integer, Integer> getPort() {
		return portMap;
	}

	public void setPort(Map<Integer, Integer> port) {
		this.portMap = port;
	}

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
