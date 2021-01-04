package net.floodlightcontroller.useraccesscontrol;

import net.floodlightcontroller.packet.Ethernet;

public class UserRoutingDecision {

    public enum UserRoutingAction{
        ALLOW,
        DENY,
        BLOCK
    }



    public UserRoutingAction getAction(Ethernet eth) {
        return UserRoutingAction.ALLOW;
    }

    public void setAction(UserRoutingAction action) {

    }
}
