package net.floodlightcontroller.internalsecurity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.restserver.IRestApiService;


public class InternalSecurity implements IFloodlightModule, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(InternalSecurity.class);

	private static final short APP_ID = 100;
	static {
		AppCookie.registerApp(APP_ID, "AntiPortScann");
	}

	// Our dependencies
	IFloodlightProviderService floodlightProviderService;
	IRestApiService restApiService;
	IDeviceService deviceService;

	//Custom LAB5
	private AttackScanner attackScanner;

	// Our internal state
	protected Map<MacAddress, Integer> hostToSyn; // map of host MAC to syn flag counter
	protected Map<MacAddress, Integer> hostToSynAck; // map of host MAC to syn-ack flag counter
	protected Map<MacAddress, Long > hostToTimestamp; // map of host MAC to timestamp


	// IFloodlightModule

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService>
	getServiceImpls() {
		Map<Class<? extends IFloodlightService>,
				IFloodlightService> m =
				new HashMap<Class<? extends IFloodlightService>,
						IFloodlightService>();
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IRestApiService.class);
		l.add(IDeviceService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);

		hostToSyn = new ConcurrentHashMap<>();
		hostToSynAck = new ConcurrentHashMap<>();

		attackScanner = new AttackScanner();

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
	}

	// IOFMessageListener

	@Override
	public String getName() {
		return InternalSecurity.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// Link discovery should go before us so we don't block LLDPs
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// We need to go before forwarding
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
			case PACKET_IN:
				return processPacketIn(sw, (OFPacketIn)msg, cntx);
			default:
				break;
		}
		log.warn("Received unexpected message {}", msg);
		return Command.CONTINUE;
	}


	/**
	 * Processes an OFPacketIn message and decides if the OFPacketIn should be dropped
	 * or the processing should continue.
	 * @param sw The switch the PacketIn came from.
	 * @param msg The OFPacketIn message from the switch.
	 * @param cntx The FloodlightContext for this message.
	 * @return Command.CONTINUE if processing should be continued, Command.STOP otherwise.
	 */
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Command ret = Command.STOP;

		if (isIpSpoofingAtack()){
			if (log.isTraceEnabled())
				log.trace("IPSpoofing detected at {} y {}",
						new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});

			// TODO: ??

		}
		if (isPortScanningAttack()){
			if (log.isTraceEnabled())
				log.trace("PortScanning detected at {} y {}",
						new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});
			// TODO: ??

		}
		if (isMaliciousRequestsAttack()){
			if (log.isTraceEnabled())
				log.trace("MaliciousRequests detected at {} y {}",
						new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});
			// TODO: ??

		} else {
			// OK
			return Command.CONTINUE;
		}

		// 1. caso TCP SYN

		// Revisar si la MAC origen está en el MAP de contadores SYN

		// Si no está, agregarlo al map de contadores SYN, SYN-ACK y al de tiempo (con la hora actual)

		// si está, revisar si está dentro de la ventana de analisis, si no está en la ventana de análsis borrarlo del map

		// si está en la ventana de análisis, revisar si longitud(SYN)-longitud(SYN-ACK)> THRESHOLD

		// si es TRUE, continuear el pipeline, si es FALSE, DROP

		// 2. Caso TCP SYN-ACK

		// Revisar si la MAC origen están al MAP de contadores SYN

		// Si está, incrementar el contador SYN-ACK

		return ret;
	}

	protected class PortScanSuspect{
		MacAddress sourceMACAddress;
		MacAddress destMACAddress;
		Integer ackCounter;
		Integer synAckCounter;
		private long startTime;

	}


}
