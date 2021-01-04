package net.floodlightcontroller.useraccesscontrol;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.useraccesscontrol.entity.User;

public class UserRoutingDecision {

    public enum UserRoutingAction{
        ALLOW,
        DENY,
        BLOCK
    }



    public UserRoutingAction getAction(User user) {

        if (user != null)
            return UserRoutingAction.ALLOW;

        return UserRoutingAction.DENY;
    }

    public void setAction(UserRoutingAction action) {

    }
}
