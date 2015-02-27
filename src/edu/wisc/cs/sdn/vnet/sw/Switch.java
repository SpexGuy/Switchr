package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{
	private static class MACAddressInfo {
		public MACAddressInfo(Iface direction) {
			this.direction = direction;
			this.createTime = System.currentTimeMillis();
		}
		Iface direction;
		long createTime;

		public boolean isExpired() {
			return (System.currentTimeMillis() - this.createTime) >= 15000;
		}
	}

	private Map<MACAddress, MACAddressInfo> macAddressMap = new HashMap<>();

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		learnPacket(etherPacket, inIface);

		Iface outgoing = findInterface(etherPacket.getDestinationMAC());
		if (outgoing != null)
			sendPacket(etherPacket, outgoing);
		else
			broadcast(etherPacket, inIface);
	}

	private void learnPacket(Ethernet packet, Iface from) {
		macAddressMap.put(packet.getSourceMAC(), new MACAddressInfo(from));
	}

	private Iface findInterface(MACAddress addr) {
		if (macAddressMap.containsKey(addr)) {
			MACAddressInfo info = macAddressMap.get(addr);
			if (info.isExpired()) {
				macAddressMap.remove(addr);
				return null;
			}
			return info.direction;
		}
		return null;
	}

	private void broadcast(Ethernet packet, Iface ignore) {
		for (Map.Entry<String, Iface> out : getInterfaces().entrySet()) {
			if (!out.getValue().equals(ignore)) {
				sendPacket(packet, out.getValue());
			}
		}
	}
}
