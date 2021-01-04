package net.floodlightcontroller.useraccesscontrol;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.useraccesscontrol.dao.UserDao;
import net.floodlightcontroller.useraccesscontrol.entity.User;
import org.slf4j.Logger;

public class UserRoutingDecision {

    protected UserDao userDao;

    public UserRoutingDecision(Logger logger) {
        userDao = new UserDao(logger);
    }

    public UserRoutingAction getAction(Ethernet eth) {

        IPv4 ip = (IPv4) eth.getPayload();
        String ip_dest = ip.getDestinationAddress().toString();
        String ip_src = ip.getSourceAddress().toString();
        String eth_dest = eth.getDestinationMACAddress().toString();
        String eth_src = eth.getSourceMACAddress().toString();
        User user_src = userDao.findUserByIpAndMac(ip_src, eth_src);
        User user_dst = userDao.findUserByIpAndMac(ip_dest, eth_dest);

        if (user_src != null || user_dst !=null)
            return UserRoutingAction.ALLOW;

        return UserRoutingAction.DENY;

    }


    public enum UserRoutingAction{
        ALLOW,
        DENY,
        BLOCK
    }




}
