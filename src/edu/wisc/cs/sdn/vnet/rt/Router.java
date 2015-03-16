package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
    public static final byte ICMP_TIME_EXCEEDED_TYPE = 11;
    public static final byte ICMP_TIME_EXCEEDED_CODE = 0;
    public static final byte ICMP_NET_UNREACHABLE_TYPE = 3;
    public static final byte ICMP_NET_UNREACHABLE_CODE = 0;
    public static final byte ICMP_HOST_UNREACHABLE_TYPE = 3;
    public static final byte ICMP_HOST_UNREACHABLE_CODE = 1;
    public static final byte ICMP_PORT_UNREACHABLE_TYPE = 3;
    public static final byte ICMP_PORT_UNREACHABLE_CODE = 3;
    public static final byte ICMP_ECHO_REQUEST_TYPE = 8;
    public static final byte ICMP_ECHO_RESPONSE_TYPE = 0;
    public static final byte ICMP_ECHO_RESPONSE_CODE = 0;

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
        System.out.println();
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
        dumpBinary(etherPacket.serialize(), " IN ");

		/********************************************************************/
		/* Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
        case Ethernet.TYPE_ARP:
            this.handleArpPacket(etherPacket, inIface);
            break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}

    private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
        ARP arpPacket = (ARP) etherPacket.getPayload();
        switch(arpPacket.getOpCode()) {
        case ARP.OP_REQUEST:
            int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
            if (targetIp == inIface.getIpAddress()) {
                sendArpReply(etherPacket, arpPacket, inIface);
            }
            break;
        case ARP.OP_REPLY:
            // TODO: really complicated queueing
            break;
        }
    }

    private void sendArpReply(Ethernet sourceEther, ARP sourceArp, Iface inIface) {
        Ethernet ether = new Ethernet();
        ARP arp = new ARP();
        ether.setPayload(arp);

        ether.setEtherType(Ethernet.TYPE_ARP);
        ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ether.setDestinationMACAddress(sourceEther.getSourceMACAddress());

        arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arp.setProtocolType(ARP.PROTO_TYPE_IP);
        arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
        arp.setProtocolAddressLength((byte)4);
        arp.setOpCode(ARP.OP_REPLY);
        arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
        arp.setSenderProtocolAddress(inIface.getIpAddress());
        arp.setTargetHardwareAddress(sourceArp.getSenderHardwareAddress());
        arp.setTargetProtocolAddress(sourceArp.getSenderProtocolAddress());

        sendPacket(ether, inIface);
    }
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
            assert(false);
            return;
        }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum) {
            System.out.println("Dropping - Bad checksum");
            return;
        }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl()) {
            System.out.println("Dropping - Bad TTL");
            sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
            return;
        }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        int ipProtocol = ipPacket.getProtocol();
        for (Iface iface : this.interfaces.values()) {
            if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
                if (ipProtocol == IPv4.PROTOCOL_ICMP) {
                    ICMP icmpPacket = (ICMP) ipPacket.getPayload();
                    if (icmpPacket.getIcmpType() == ICMP_ECHO_REQUEST_TYPE) {
                        System.out.println("Dropping - ICMP echo request");
                        sendEchoResponse(inIface, etherPacket, ipPacket, icmpPacket);
                    } else {
                        System.out.println("Non-echo ICMP packet bound for interface");
                    }
                } else if (ipProtocol == IPv4.PROTOCOL_TCP || ipProtocol == IPv4.PROTOCOL_UDP) {
                    System.out.println("Dropping - TCP or UDP bound for interface");
                    sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_PORT_UNREACHABLE_TYPE, ICMP_PORT_UNREACHABLE_CODE);
                } else {
                    System.out.println("Dropping - NOT TCP or UDP bound for interface");
                }
                return;
            }
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
            assert(false);
            return;
        }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, ICMP Destination Net Unreachable
        if (null == bestMatch) {
            System.out.println("Dropping - No Route Entry");
            sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_NET_UNREACHABLE_TYPE, ICMP_NET_UNREACHABLE_CODE);
            return;
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface) {
            System.out.println("Dropping - outgoing interface == incoming interface");
            return;
        }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop) {
            nextHop = dstAddr;
        }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry) {
            System.out.println("Dropping - No ARP Entry");
            sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_HOST_UNREACHABLE_TYPE, ICMP_HOST_UNREACHABLE_CODE);
            return;
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

    private void sendICMPIPPacket(Iface source, Ethernet etherSource, IPv4 ipSource, byte type, byte code) {
        System.out.println("Send ICMP IP packet");
        byte[] ipBytes = ipSource.serialize();
        int ipHeaderSize = ipSource.getHeaderLength() * 4;
        byte[] packetPayload = new byte[4 + ipHeaderSize + 8];
        ByteBuffer payload = ByteBuffer.wrap(packetPayload);
        payload.rewind();
        payload.putInt(0); // 4 bytes of padding
        payload.put(ipBytes, 0, Math.min(ipBytes.length, ipHeaderSize + 8));
        sendICMPPacket(source, etherSource, ipSource, type, code, packetPayload);
    }

    private void sendEchoResponse(Iface source, Ethernet etherSource, IPv4 ipSource, ICMP icmpSource) {
        System.out.println("Send ICMP Echo");
        sendICMPPacket(source, etherSource, ipSource, ICMP_ECHO_RESPONSE_TYPE, ICMP_ECHO_RESPONSE_CODE, icmpSource.getPayload().serialize());
    }

    private void sendICMPPacket(Iface source, Ethernet etherSource, IPv4 ipSource, byte type, byte code, byte[] payload) {
        // create packet
        Ethernet ether = new Ethernet();
        IPv4 ip = new IPv4();
        ICMP icmp = new ICMP();
        Data data = new Data();
        ether.setPayload(ip);
        ip.setPayload(icmp);
        icmp.setPayload(data);

        // figure out where the ICMP packet needs to hop next
        int destinationAddress = ipSource.getSourceAddress();
        RouteEntry target = routeTable.lookup(destinationAddress);
        if (target == null) {
            System.out.printf("can't find ICMP target: %08X\n", destinationAddress);
            return;
        }
        int nextHop = target.getGatewayAddress();
        if (nextHop == 0)
            nextHop = destinationAddress;
        ArpEntry targetArp = this.arpCache.lookup(nextHop);
        if (targetArp == null) {
            System.out.printf("can't find ICMP target MAC for %08X\n", nextHop);
            return;
        }

        // set up routing and other information
        ether.setEtherType(Ethernet.TYPE_IPv4);
        ether.setSourceMACAddress(source.getMacAddress().toBytes());
        ether.setDestinationMACAddress(targetArp.getMac().toBytes());

        ip.setTtl((byte)64);
        ip.setProtocol(IPv4.PROTOCOL_ICMP);
        ip.setSourceAddress(source.getIpAddress());
        ip.setDestinationAddress(destinationAddress);

        icmp.setIcmpType(type);
        icmp.setIcmpCode(code);

        data.setData(payload);

        // send packet
        System.out.println("<------ Sending ICMP packet: " +
                ether.toString().replace("\n", "\n\t"));
        dumpBinary(ether.serialize(), "OUT ");

        this.sendPacket(ether, source);
    }

    private void dumpBinary(byte[] data, String name4) {
        System.out.printf("%s : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n", name4);
        System.out.println("------------------------------------------------------");
        int numRows = data.length/16;
        int numExtra = data.length%16;
        for (int r = 0; r < numRows; r++) {
            System.out.printf("%04X :", r*16);
            for (int c = 0; c < 16; c++) {
                System.out.printf(" %02X", data[r * 16 + c]);
            }
            System.out.println();
        }
        System.out.printf("%04X :", numRows*16);
        for (int c = 0; c < numExtra; c++) {
            System.out.printf(" %02X", data[numRows*16 + c]);
        }
        System.out.println();
    }
}
