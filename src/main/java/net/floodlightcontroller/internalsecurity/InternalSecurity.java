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
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.restserver.IRestApiService;


public class InternalSecurity implements IFloodlightModule, IOFMessageListener {
	private static final Object ENABLED_STR = "enable";
	private static final Integer MRA_TRESHOLD_MAX_DST = 200;
	private static final Integer MRA_TRESHOLD_MAX_SRC = 20;
	private static final Integer MRA_COUNTER_TIMER = 5000; //ms
	
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

	protected Map<MacAddress, PortScanSuspect> macToSuspect; // <Mac origen, PortScanSuspect
	private boolean isEnabled = false;
	private Map<String, Map<String,Object[]>> ipDstToData = new HashMap<>(); // Tiene todos los datos para Malicious Request DDoS
	//[0] para el contador (Integer), [1] para el tiempo (long) 



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
		
		updateData(eth);//falso si se crea un nuevo entry o si no es ipv4


		// Just IP Spoofing Attack scanner
/*
		if (isIpSpoofingAttack(eth, sw, msg, cntx)){
				//log.info("IPSpoofing detected at {} y {}", new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});

			decision = new RoutingDecision(sw.getId(), inPort,
					IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
					IRoutingDecision.RoutingAction.DROP);
			decision.addToContext(cntx);
			return Command.CONTINUE;

		}*/

		if (isPortScanningAttack(eth,sw,msg,cntx)){
				log.info("PortScanning detected at {} y {}", new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});
			
			//	Bloquear todo el tráfico del source


			decision = new RoutingDecision(sw.getId(), inPort, 
					IDeviceService.fcStore.get(cntx,IDeviceService.CONTEXT_SRC_DEVICE), 
					IRoutingDecision.RoutingAction.DROP_ALL);
			decision.addToContext(cntx);
			return Command.CONTINUE;

		}

		if (isMaliciousRequestsAttack(eth)){
				log.info("MaliciousRequests detected at {} y {}", new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});
			

			decision = new RoutingDecision(sw.getId(), inPort, 
					IDeviceService.fcStore.get(cntx,IDeviceService.CONTEXT_SRC_DEVICE), 
					IRoutingDecision.RoutingAction.DROP);
			decision.addToContext(cntx);
			return Command.CONTINUE;
		}

		return ret;
	}

	private boolean updateData(Ethernet eth) {
		//verificar si es IPv4
		if (!eth.getEtherType().equals(EthType.IPv4))
			return false;
		IPv4 ipv4 = (IPv4) eth.getPayload();
		//verificar si es TCP
		if (!ipv4.getProtocol().equals(IpProtocol.TCP))
			return false;
		TCP tcp = (TCP) ipv4.getPayload();
		
		MacAddress sourceMAC = eth.getSourceMACAddress();
		MacAddress destinationMAC = eth.getDestinationMACAddress();
		if( tcp.getFlags() ==  (short) 0x0f ) { //Validar si es ACK
			sourceMAC = eth.getDestinationMACAddress();
			destinationMAC = eth.getSourceMACAddress();
		}
		
		// START case ya existe el sujeto
		if(macToSuspect.containsKey(sourceMAC)) { 	//Ya existe el sujeto
		
			PortScanSuspect sujeto = macToSuspect.get(sourceMAC);
			
			
			// START bloque para el data externo
			Data dataExterior = sujeto.getData();
			
			// Bloque para sumar 1 al contador SYN o ACK
			if( tcp.getFlags() ==  (short) 0x02 ) { //Validar si es SYN
				dataExterior.setSynCounter(dataExterior.getSynCounter() + 1);		//SUMAR +1
			}
			else if( tcp.getFlags() ==  (short) 0x0f ) { //Validar si es ACK
				dataExterior.setSynAckCounter(dataExterior.getSynAckCounter() + 1); //SUMAR +1
			}
			
			// Bloque para sumar 1 al contador de puerto destino TCP
			if( dataExterior.getPort().containsKey(tcp.getDestinationPort().getPort())) { //VER si contiene el puerto destino
				dataExterior.getPort().replace( tcp.getDestinationPort().getPort(), dataExterior.getPort().get(tcp.getDestinationPort().getPort())+1 ); // sumar +1
			}else {
				dataExterior.getPort().put(tcp.getDestinationPort().getPort(), 1); // Empezar el contador en 1
			}
			// END bloque para el data externo
			
			
			
			// START bloque para el data interno (pareja Source-Destino)
			if(sujeto.getDestinos().containsKey(destinationMAC)) { //checkear si existe ya una relacion src-dst
				//START bloque para aumentar contadores
				Data dataInterior = sujeto.getDestinos().get(destinationMAC);
				
				// Bloque para sumar 1 al contador SYN o ACK
				if( tcp.getFlags() ==  (short) 0x02 ) { //Validar si es SYN
					dataInterior.setSynCounter(dataInterior.getSynCounter() + 1);		//SUMAR +1
				}
				else if( tcp.getFlags() ==  (short) 0x0f ) { //Validar si es ACK
					dataInterior.setSynAckCounter(dataInterior.getSynAckCounter() + 1); //SUMAR +1
				}
				
				// Bloque para sumar 1 al contador de puerto destino TCP
				if( dataInterior.getPort().containsKey(tcp.getDestinationPort().getPort())) { //VER si contiene el puerto destino
					dataInterior.getPort().replace( tcp.getDestinationPort().getPort(), dataInterior.getPort().get(tcp.getDestinationPort().getPort())+1 ); // sumar +1
				}else {
					dataInterior.getPort().put(tcp.getDestinationPort().getPort(), 1); // Empezar el contador en 1
				}
				// END bloque de 'ya existe relacion src-dst'
				
				// START bloque crear relacion src-dst
			}else { // crear una relacion src-dst
				Data dataInterior = new Data();
				
				Map<Integer,Integer> map = new HashMap<Integer,Integer>();
				map.put(tcp.getDestinationPort().getPort(), 1);
				dataInterior.setPort(map);
				dataInterior.setStartTime(System.currentTimeMillis());
				dataInterior.setSynCounter(0);
				dataInterior.setSynAckCounter(0);
				
				if( tcp.getFlags() ==  (short) 0x02 ) { //Validar si es SYN
					dataInterior.setSynCounter(1);		// Establecer en 1
				}
				else if( tcp.getFlags() ==  (short) 0x0f ) { //Validar si es ACK
					dataInterior.setSynAckCounter(1); // Establecer en 1
				}
				
				sujeto.getDestinos().put(eth.getDestinationMACAddress(), dataInterior);
			}
			// END bloque para el data interno
			return true;
		}
		//END CASE ya existe el sujeto
		
		// START bloque crear sujeto
		else {
			PortScanSuspect sujeto = new PortScanSuspect();	
		
			// START Data Exterior
			Data dataExterior = new Data();
			dataExterior.setStartTime(System.currentTimeMillis());
			//bloque para syn/synAck counters
			dataExterior.setSynCounter(0);
			dataExterior.setSynAckCounter(0);
			
			if( tcp.getFlags() ==  (short) 0x02 ) { //Validar si es SYN
				dataExterior.setSynCounter(1);		//SET 1
			}
			else if( tcp.getFlags() ==  (short) 0x0f ) { //Validar si es ACK
				dataExterior.setSynAckCounter(1); //SET 1
			}
			
			Map<Integer,Integer> portMapExterior = new HashMap<Integer,Integer>();
			portMapExterior.put(tcp.getDestinationPort().getPort(), 1);
			dataExterior.setPort(portMapExterior);
			sujeto.setData(dataExterior);
			// FIN data exterior
			
			// Parte Interior ( relacion src-dst)
			Map<MacAddress,Data> map = new HashMap<MacAddress,Data>();
			Data dataInterior = new Data();
			Map<Integer,Integer> portMapInterior = new HashMap<Integer,Integer>();
			portMapInterior.put(tcp.getDestinationPort().getPort(), 1);
			dataInterior.setStartTime(System.currentTimeMillis());
			
			dataInterior.setSynCounter(0);
			dataInterior.setSynAckCounter(0);
			
			if( tcp.getFlags() ==  (short) 0x02 ) { //Validar si es SYN
				dataInterior.setSynCounter(1);		//SET 1
			}
			else if( tcp.getFlags() ==  (short) 0x0f ) { //Validar si es ACK
				dataInterior.setSynAckCounter(1); //SET 1
			}
			dataInterior.setPort(portMapInterior);
			
			
			map.put(eth.getDestinationMACAddress(), dataInterior);
			sujeto.setDestinos(map);
			
			macToSuspect.put(eth.getSourceMACAddress(), sujeto);
			return false;
			
		}
	}
	
	private boolean isMaliciousRequestsAttack(Ethernet eth) { //falso si no es IPv4
		//verificar si es IPv4
		if (!eth.getEtherType().equals(EthType.IPv4))
			return false;
		
		Object[] arr = new Object[2];
		Map<String, Object[]> ipSrcToCount = new HashMap<>();
		
		IPv4 ipv4 = (IPv4) eth.getPayload();
		String Source = ipv4.getSourceAddress().toString();
		String Destination = ipv4.getDestinationAddress().toString();
		if(ipDstToData.containsKey(Destination)) {
			
			if(ipDstToData.get(Destination).containsKey(Source)) {
				Integer contador = ((Integer) ipDstToData.get(Destination).get(Source)[0] )+ 1;
				arr[0] = contador;
				long tiempo = (long) ipDstToData.get(Destination).get(Source)[1];
				if(System.currentTimeMillis() - tiempo > MRA_COUNTER_TIMER) {
					arr[0] = 1;
				}
				arr[1] = System.currentTimeMillis();
				
				
				ipDstToData.get(Destination).put(Source,arr);
				Integer total = 0;
				//Iteracion para saber el total
				ArrayList<String> borrar = new ArrayList<String>();
				for (Map.Entry<String, Object[]> entry : ipDstToData.get(Destination).entrySet()) {
					Integer counter = (Integer) entry.getValue()[0];
					long tiempo1 = (long) entry.getValue()[1];
					if(System.currentTimeMillis() - tiempo1 > MRA_COUNTER_TIMER) {
						if(entry.getKey().compareTo(Source)==0) {
							counter = 1;
						}else {
							counter = 0;
							borrar.add(entry.getKey());
						}
					}
					total = total + counter;
				}
				for (int i = 0; i < borrar.size(); i++) {
					ipDstToData.get(Destination).remove(borrar.get(i));
				}
				
				//toma de deciciones
				if(total > MRA_TRESHOLD_MAX_DST || contador > MRA_TRESHOLD_MAX_SRC) {
					return true;
				}else {
					return false;
				}
				
				
				
			}else {
				arr[0] = 1;
				arr[1] = System.currentTimeMillis();
				ipDstToData.get(Destination).put(Source, arr);
				return false;
			}
		}else {
			arr[0] = 1;
			arr[1] = System.currentTimeMillis();
			ipSrcToCount.put(Source, arr);
			ipDstToData.put(Destination, ipSrcToCount);
			return false;
		}
		
		
	}

	private boolean isPortScanningAttack(
			Ethernet eth, IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		
		if(macToSuspect.containsKey(eth.getSourceMACAddress())) {
		
			
			
			if ((System.currentTimeMillis() - macToSuspect.get(eth.getSourceMACAddress()).getData().getStartTime()) > 1800) {
				 macToSuspect.get(eth.getSourceMACAddress()).getData().setStartTime(System.currentTimeMillis());
				 macToSuspect.get(eth.getSourceMACAddress()).getData().setSynCounter(0);
				 macToSuspect.get(eth.getSourceMACAddress()).getData().setSynAckCounter(0);
            }
			PortScanSuspect sospechoso = macToSuspect.get(eth.getSourceMACAddress());
			Data informacion = sospechoso.getData();
			int contadorSYN = informacion.getSynCounter(); 
			int contadorACK = informacion.getSynAckCounter(); 
			int diferencia = contadorSYN - contadorACK; 
			int threshold = 5; // MODIFICAR
            

			long windowTime = System.currentTimeMillis() - informacion.getStartTime(); ////
			long metric;
			if(windowTime == 0)
				metric= (long)0;
			else
				metric = (contadorSYN*1000)/windowTime;

			int threshold2 = 20; // MODIFICAR 

            log.info("metric: "+metric+", windowtime: {}, diferencia: {}", windowTime, diferencia);

			if (diferencia > threshold || metric > threshold2 )
			{ //log.info("Port Scanning Attack detected: {}", eth.getSourceMACAddress());
				return true;
			}


			//log.info("No Port Scanning Attack detected: {}",eth.getSourceMACAddress());
			return false;
				
		}
		return false;
	}

	private boolean isIpSpoofingAttack(Ethernet eth, IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
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

		if (device == null){
		    log.warn("Device is null");
        }
		else if (device.getIPv4Addresses().length == 0 ){
		    log.warn("No device");
        }
        else if (device.getIPv4Addresses().length > 1 ){
            log.warn("More than on device");
        }
        else if (!device.getIPv4Addresses()[0].equals(ip.getSourceAddress()))
        {
            log.warn("Ip !");
        }
        else {
            log.warn("??????");
        }

		if (device == null ||
				(device.getIPv4Addresses().length == 0) ||
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

}
