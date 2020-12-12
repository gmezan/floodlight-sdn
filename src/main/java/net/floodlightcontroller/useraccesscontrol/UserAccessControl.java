package net.floodlightcontroller.useraccesscontrol;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.firewall.FirewallRule;
import net.floodlightcontroller.firewall.RuleMatchPair;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.useraccesscontrol.db.UserDao;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class UserAccessControl implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected static Logger logger;
    protected UserDao userDao;
    protected UserRoutingDecision userRoutingDecision;

    public static final int FLOWMOD_IDLE_TIMEOUT_UAC = 30;
    public static final int FLOWMOD_HARD_TIMEOUT_UAC = 30;

    protected IPv4Address subnet_mask = IPv4Address.of("255.255.255.0");

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
            case PACKET_IN:
                IRoutingDecision decision = null;
                if (cntx != null) {
                    decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
                    return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
                }
                break;
            default:
                break;
        }
        return Command.CONTINUE;
    }

    public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));

        logger.info("Making a decision.");
        // Allowing L2 broadcast + ARP broadcast request (also deny malformed
        // broadcasts -> L2 broadcast + L3 unicast)
        if (eth.isBroadcast()) {
            boolean allowBroadcast = true;
            // the case to determine if we have L2 broadcast + L3 unicast (L3 broadcast default set to /24 or 255.255.255.0)
            // don't allow this broadcast packet if such is the case (malformed packet)
            if ((eth.getPayload() instanceof IPv4) && !isIPBroadcast(((IPv4) eth.getPayload()).getDestinationAddress())) {
                allowBroadcast = false;
            }
            if (allowBroadcast) {
                if (logger.isTraceEnabled()) {
                    logger.trace("Allowing broadcast traffic for PacketIn={}", pi);
                }
                decision = new RoutingDecision(sw.getId(), inPort,
                        IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
                        IRoutingDecision.RoutingAction.MULTICAST);
                decision.addToContext(cntx);
            } else {
                if (logger.isTraceEnabled()) {
                    logger.trace("Blocking malformed broadcast traffic for PacketIn={}", pi);
                }
                decision = new RoutingDecision(sw.getId(), inPort,
                        IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
                        IRoutingDecision.RoutingAction.DROP);
                decision.addToContext(cntx);
            }
            return Command.CONTINUE;
        }
        // check if we have a matching rule for this packet/flow and no decision has been made yet
        if (decision == null) {
            // verify the packet
            logger.info("Verifying with UserRoutingDecision.");

            userRoutingDecision.verify();

            switch (userRoutingDecision.getAction()){
                case DENY:
                    decision = new RoutingDecision(sw.getId(), inPort,
                            IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
                            IRoutingDecision.RoutingAction.UAC_DROP);
                    decision.addToContext(cntx);
                    if (logger.isTraceEnabled()) {
                        logger.trace("Denying access to flow with PacketIn={}", pi);
                    }
                    break;
                case ALLOW:
                    decision = new RoutingDecision(sw.getId(), inPort,
                            IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
                            IRoutingDecision.RoutingAction.UAC_FORWARD);
                    decision.addToContext(cntx);
                    if (logger.isTraceEnabled()) {
                        logger.trace("Allowing access to flow with PacketIn={}", pi);
                    }
                    break;
                case BLOCK:
                    break;
            }
        }

        return Command.CONTINUE;
    }

    @Override
    public String getName() {
        return UserAccessControl.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        logger = LoggerFactory.getLogger(UserAccessControl.class);
        userDao = new UserDao(logger);
        userRoutingDecision = new UserRoutingDecision();

    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }

    protected boolean isIPBroadcast(IPv4Address ip) {
        // inverted subnet mask
        IPv4Address inv_subnet_mask = subnet_mask.not();
        return ip.and(inv_subnet_mask).equals(inv_subnet_mask);
    }

}
