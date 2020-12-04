package net.floodlightcontroller.statistics.lab4package;

import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.types.DatapathId;

public class NodeFlowTuple implements Comparable<NodeFlowTuple> {

    protected DatapathId nodeId;
    protected OFFlowStatsEntry flowModStats;

    public NodeFlowTuple(){}

    public NodeFlowTuple(DatapathId id, OFFlowStatsEntry flow){
        this.flowModStats = flow;
        this.nodeId = id;
    }

    public DatapathId getNodeId() {
        return nodeId;
    }

    public void setNodeId(DatapathId nodeId) {
        this.nodeId = nodeId;
    }

    public OFFlowStatsEntry getFlowModStats() {
        return flowModStats;
    }

    public void setFlowModStats(OFFlowStatsEntry flowModStats) {
        this.flowModStats = flowModStats;
    }

    @Override
    public int compareTo(NodeFlowTuple o) {
        return o.flowModStats.equals(this.flowModStats) && o.nodeId.equals(this.nodeId)? 0:1;
    }
}
