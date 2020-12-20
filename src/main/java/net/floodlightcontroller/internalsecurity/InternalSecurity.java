package net.floodlightcontroller.internalsecurity;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
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
	private static final Object ENABLED_STR = "enable";
	protected static Logger log = LoggerFactory.getLogger(InternalSecurity.class);

	private static final short APP_ID = 100;
	static {
		AppCookie.registerApp(APP_ID, "InternalSecurity");
	}

	// Our dependencies
	IFloodlightProviderService floodlightProviderService;
	IRestApiService restApiService;
	IDeviceService deviceService;


	// Our internal state
	protected Map<MacAddress, PortScanSuspect> macToSuspect;
	private boolean isEnabled = false;


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
		deviceService = context.getServiceImpl(IDeviceService.class);
		macToSuspect = new ConcurrentHashMap<>();

		Map<String, String> config = context.getConfigParams(this);

		if (config.containsKey(ENABLED_STR)) {
			try {
				isEnabled = Boolean.parseBoolean(config.get(ENABLED_STR).trim());
			} catch (Exception e) {
				log.error("Could not parse '{}'. Using default of {}", ENABLED_STR, isEnabled);
			}
		}
		log.info("Internal Security {}", isEnabled ? "enabled" : "disabled");



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
		if (!this.isEnabled) {
			return Command.CONTINUE;
		}

		switch (msg.getType()) {
			case PACKET_IN:
				IRoutingDecision decision = null;
				if (cntx != null) {
					decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
					return this.processPacketIn(sw, (OFPacketIn) msg, decision, cntx);
				}
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
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, IRoutingDecision decision, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPort inPort = (msg.getVersion().compareTo(OFVersion.OF_12) < 0 ? msg.getInPort() : msg.getMatch().get(MatchField.IN_PORT));

		Command ret = Command.CONTINUE;


		log.info("PacketIn Processing on InternalSecurity");
		
		updateData(eth);

		if (decision != null){
			log.info("Decision found");
		}


		if (isIpSpoofingAttack(eth, sw, msg)){
			if (log.isTraceEnabled())
				log.trace("IPSpoofing detected at {} y {}",
						new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});

			// TODO: ??
			decision = new RoutingDecision(sw.getId(), inPort,
					IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
					IRoutingDecision.RoutingAction.DROP);
			decision.addToContext(cntx);
			return Command.CONTINUE;

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

		}

		return ret;
	}

	private boolean updateData(Ethernet eth) {
		// TODO Updatear los contadores en la estructura de datos
		// TODO Retornar verdadero si ya existia, falso si no existia.
		return false;
	}
	
	private boolean isMaliciousRequestsAttack() {
		return false;
	}

	private boolean isPortScanningAttack() {
		
		// 1. caso TCP SYN

				// Revisar si la MAC origen está en el MAP de contadores SYN

				//	hostToTimestamp.put(eth.getSourceMACAddress(), System.currentTimeMillis());

				// Si no está, agregarlo al map de contadores SYN, SYN-ACK y al de tiempo (con la hora actual)

				// si está, revisar si está dentro de la ventana de analisis, si no está en la ventana de análsis borrarlo del map

				// si está en la ventana de análisis, revisar si longitud(SYN)-longitud(SYN-ACK)> THRESHOLD

				// si es TRUE, continuear el pipeline, si es FALSE, DROP

				// 2. Caso TCP SYN-ACK

				// Revisar si la MAC origen están al MAP de contadores SYN

				// Si está, incrementar el contador SYN-ACK
		
		return false;
	}

	private boolean isIpSpoofingAttack(Ethernet eth, IOFSwitch sw, OFPacketIn msg) {
		//is IPv4?
		if (!eth.getEtherType().equals(EthType.IPv4))
			return false;

		IPv4 ip = (IPv4) eth.getPayload();

		Iterator<? extends IDevice> it = deviceService.queryDevices(
				eth.getSourceMACAddress(),
				null,
				IPv4Address.NONE,
				IPv6Address.NONE,
				sw.getId(),
				OFPort.ZERO);

		IDevice device = it.hasNext()? it.next():null;

		if (device==null ||
				(device.getIPv4Addresses().length > 1) ||
				!device.getIPv4Addresses()[0].equals(ip.getSourceAddress())
		)
		{
			log.info("IP Spoofing Attack detected: {}", ip.getSourceAddress());
			return true;
		}

		log.info("Device exists. Not IP Spoofing Attack detected: {}", ip.getSourceAddress());
		return false;
	}

	protected class Sujeto{
		Map<MacAddress, Data> datos;
	}


}
