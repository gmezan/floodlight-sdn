package net.floodlightcontroller.internalsecurity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
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
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
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


	// Our internal state
	protected Map<MacAddress, PortScanSuspect> macToSuspect; // <Mac origen, PortScanSuspect


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

		macToSuspect = new ConcurrentHashMap<>();


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
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Command ret = Command.STOP;
		
		
		updateData(eth);

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

		return ret;
	}

	private boolean updateData(Ethernet eth) {
		IPv4 ipv4 = (IPv4) eth.getPayload();
		TCP tcp = (TCP) ipv4.getPayload();
		
		
		// TODO Updatear los contadores en la estructura de datos
		
		// START case ya existe el sujeto
		if(macToSuspect.containsKey(eth.getSourceMACAddress())) { 	//Ya existe el sujeto
		
			PortScanSuspect sujeto = macToSuspect.get(eth.getSourceMACAddress());
			
			
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
			if(sujeto.getDestinos().containsKey(eth.getDestinationMACAddress())) { //checkear si existe ya una relacion src-dst
				//START bloque para aumentar contadores
				Data dataInterior = sujeto.getDestinos().get(eth.getDestinationMACAddress());
				
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

	private boolean isIpSpoofingAtack() {
		
		return false;
	}

}
