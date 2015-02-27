package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
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
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("Dropped! - not IPv4");
			return;
		}

		IPv4 packet = (IPv4) etherPacket.getPayload();
		if (!verifyChecksum(packet)) {
			System.out.println("Dropped! - invalid checksum");
			return;
		}

		int newTtl = packet.getTtl() - 1;
		if (newTtl <= 0) {
			System.out.println("Dropped! - arthritis");
			return;
		}
		packet.setTtl((byte)newTtl);

		if (isInterfaceBound(packet)) {
			System.out.println("Dropped! - bound for interface");
			return;
		}

		RouteEntry target = routeTable.lookup(packet.getDestinationAddress());
		if (target == null) {
			System.out.println("Dropped! - unknown destination address");
			return;
		}

		int destination = target.getDestinationAddress();
		if (destination == 0) {
			destination = packet.getDestinationAddress();
		}

		ArpEntry arp = arpCache.lookup(destination);
		if (arp == null) {
			System.out.println("Dropped! - unknown arp entry");
			return;
		}

		etherPacket.setSourceMACAddress(arp.getMac().toBytes());
		sendPacket(etherPacket, target.getInterface());

		/********************************************************************/
	}

	private boolean isInterfaceBound(IPv4 packet) {
		for (Map.Entry<String, Iface> iface : interfaces.entrySet()) {
			if (iface.getValue().getIpAddress() == packet.getDestinationAddress())
				return true;
		}
		return false;
	}

	private static boolean verifyChecksum(IPv4 packet) {
		ByteBuffer bb = ByteBuffer.wrap(packet.serialize());
		bb.rewind();
		int headerLength = packet.getHeaderLength();
		int accumulation = 0;
		for (int i = 0; i < headerLength * 2; ++i) {
			short part = bb.getShort();
			System.out.printf("%04X", part);
			if (i != 5) // skip the checksum
				accumulation += 0xffff & part;
			else
				System.out.print(" <- Checksum");
			System.out.println();
		}
		accumulation = ((accumulation >> 16) & 0xffff)
				+ (accumulation & 0xffff);
		short checksum = (short) (~accumulation & 0xffff);
		System.out.printf("Us: %04X Them: %04X\n", checksum, packet.getChecksum());
		return checksum == packet.getChecksum();
	}
}
