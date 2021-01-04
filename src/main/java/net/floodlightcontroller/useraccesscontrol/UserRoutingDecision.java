package net.floodlightcontroller.useraccesscontrol;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.useraccesscontrol.dao.UserDao;
import net.floodlightcontroller.useraccesscontrol.entity.User;
import org.slf4j.Logger;

public class UserRoutingDecision {

    public enum UserRoutingAction{
        ALLOW,
        DENY,
        BLOCK
    }



    public UserRoutingAction getAction(User user_src, User user_dest) {

        if (user_src != null || user_dest !=null)
            return UserRoutingAction.ALLOW;

        return UserRoutingAction.DENY;
    }


}
