package net.floodlightcontroller.internalsecurity;

import java.util.Map;

import org.projectfloodlight.openflow.types.MacAddress;



public class PortScanSuspect {
	private Map<MacAddress, Data> destinos; // Data pero por pareja Source-Destino
	private Data data;						// Ver Objeto Data.java
	
	public Map<MacAddress, Data> getDestinos() {
		return destinos;
	}
	public void setDestinos(Map<MacAddress, Data> destinos) {
		this.destinos = destinos;
	}
	public Data getData() {
		return data;
	}
	public void setData(Data data) {
		this.data = data;
	}
}
