package net.floodlightcontroller.useraccesscontrol;

public class UserRoutingDecision {

    private UserRoutingAction action;

    public void verify() {

        // Verify with DB

        this.action = UserRoutingAction.ALLOW;
    }

    public enum UserRoutingAction{
        ALLOW,
        DENY,
        BLOCK
    }



    public UserRoutingAction getAction() {
        return action;
    }

    public void setAction(UserRoutingAction action) {
        this.action = action;
    }
}
