package net.floodlightcontroller.useraccesscontrol;

public class UserRoutingDecision {

    public enum UserRoutingAction{
        ALLOW,
        DENY,
        BLOCK
    }



    public UserRoutingAction getAction() {
        return UserRoutingAction.ALLOW;
    }

    public void setAction(UserRoutingAction action) {

    }
}
