package net.floodlightcontroller.useraccesscontrol;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.useraccesscontrol.entity.User;

public class UserRoutingDecision {

    public enum UserRoutingAction{
        ALLOW,
        DENY,
        BLOCK
    }



    public UserRoutingAction getAction(User eth) {
        return UserRoutingAction.ALLOW;
    }

    public void setAction(UserRoutingAction action) {

    }
}
