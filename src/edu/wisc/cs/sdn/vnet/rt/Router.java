package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;
import java.util.*;

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

    public static final int RIP_ADDRESS = 0xE0000009; //224.0.0.9

    private static final byte BC = (byte) 0xFF;
    public static final byte[] BROADCAST_MAC = {BC,BC,BC,BC,BC,BC};
    public static final byte[] ZERO_MAC = {0,0,0,0,0,0};

    // THE ORDER OF LOCKING:
    // 1. delayedSends
    // 2. this

    private class ArpLookupChecker extends TimerTask {
        @Override
        public void run() {
            updateArpStatus();
        }
    }

    private static class WaitingPacket {
        public WaitingPacket(Iface inIface, Ethernet ether, IPv4 ip) {
            this.inIface = inIface;
            this.ether = ether;
            this.ip = ip;
        }
        public Iface inIface;
        public Ethernet ether;
        public IPv4 ip;
    }

    private class ArpDelayedSend {
        int numAttempts = 0;
        List<WaitingPacket> waitingPackets = new LinkedList<WaitingPacket>();
        int targetIP;
        Iface outIface;

        public ArpDelayedSend(int targetIP, Iface outIface) {
            this.targetIP = targetIP;
            this.outIface = outIface;
        }

        private synchronized void addPacket(Iface inIface, Ethernet ether, IPv4 ip) {
            waitingPackets.add(new WaitingPacket(inIface, ether, ip));
        }

        public synchronized boolean tryAgain() {
            if (numAttempts >= 3) {
                dropAllPackets();
                return false;
            }
            ++numAttempts;
            broadcastArpRequest(outIface, targetIP);
            return true;
        }

        private synchronized void dropAllPackets() {
            for (WaitingPacket e : waitingPackets) {
                sendICMPIPPacket(e.inIface, e.ether, e.ip, ICMP_HOST_UNREACHABLE_TYPE, ICMP_HOST_UNREACHABLE_CODE);
            }
            waitingPackets = null;
        }

        private synchronized void register(ARP info) {
            MACAddress mac = new MACAddress(info.getSenderHardwareAddress());
            int ip = ByteBuffer.wrap(info.getSenderProtocolAddress()).getInt();
            arpCache.insert(mac, ip);
            for (WaitingPacket p : waitingPackets) {
                forwardIpPacket(p.ether, p.inIface);
            }
            waitingPackets = null;
        }
    }

	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

    private Timer arpUpdater;

    private Map<Integer, ArpDelayedSend> delayedSends = new HashMap<>();

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
        this.arpUpdater = new Timer(true);
        this.arpUpdater.schedule(new ArpLookupChecker(), 1000, 1000);
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

    public void runRIP() {
        System.out.println("Running RIP");
        // add direct subnets
        for (Iface i : interfaces.values()) {
            routeTable.insert(i.getIpAddress(), 0, i.getSubnetMask(), i, 1);
        }
        System.out.println("Starting route table:");
        System.out.println(routeTable);
        broadcastRIPPackets(RIPv2.COMMAND_REQUEST, null);
    }

    private void replyToRIP(Ethernet source, Iface outIface) {
        System.out.println("Reply to RIP");
        Ethernet out = generateRIPPacket(RIPv2.COMMAND_RESPONSE, source.getSourceMACAddress());
        sendRIPPacket(out, outIface);
    }

    private void broadcastRIPPackets(byte command, Iface exclude) {
        System.out.println("Broadcasting RIP packets");
        Ethernet ether = generateRIPPacket(command, BROADCAST_MAC);

        // SPAM YOUR FRIENDS WITH STATUS UPDATES!!!
        for (Iface iface : interfaces.values()) {
            if (iface == exclude)
                continue;
            sendRIPPacket(ether, iface);
        }
    }

    private Ethernet generateRIPPacket(byte command, byte[] destinationMac) {
        Ethernet ether = new Ethernet();
        IPv4 ip = new IPv4();
        UDP udp = new UDP();
        RIPv2 rip = routeTable.makeRIPPacket();
        ether.setPayload(ip);
        ip.setPayload(udp);
        udp.setPayload(rip);

        rip.setCommand(command);
        udp.setSourcePort(UDP.RIP_PORT);
        udp.setDestinationPort(UDP.RIP_PORT);
        ip.setDestinationAddress(RIP_ADDRESS);
        ip.setProtocol(IPv4.PROTOCOL_UDP);
        ether.setDestinationMACAddress(destinationMac);
        ether.setEtherType(Ethernet.TYPE_IPv4);

        return ether;
    }

    private void sendRIPPacket(Ethernet ether, Iface iface) {
        IPv4 ip = (IPv4) ether.getPayload();
        ip.setSourceAddress(iface.getIpAddress());
        ether.setSourceMACAddress(iface.getMacAddress().toBytes());
        System.out.println("Sending RIP packet to " + iface.getName());
        dumpBinary(ether.serialize(), "RIP ");
        sendPacket(ether, iface);
    }

    private void handleRIPPacket(Ethernet ether, Iface inIface) {
        System.out.println("Handle RIP packet");
        IPv4 ip = (IPv4) ether.getPayload();
        RIPv2 rip = (RIPv2) ip.getPayload().getPayload();
        if (routeTable.updateAll(ip.getSourceAddress(), rip, inIface)) {
            System.out.println("Route table updated!");
            System.out.println(routeTable);
            // Don't ignore inIface, since it may have multiple routers on it.
            // Then again, they would have received the offending update.
            // TODO: Can we safely exclude inIface if not request?
            broadcastRIPPackets(RIPv2.COMMAND_RESPONSE, null);
        } else if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
            replyToRIP(ether, inIface);
        }
    }

    /**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
        if (!arpCache.load(arpCacheFile)) {
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
            IPv4 ip = (IPv4) etherPacket.getPayload();
            if (ip.getDestinationAddress() == RIP_ADDRESS && ip.getProtocol() == IPv4.PROTOCOL_UDP) {
                UDP udp = (UDP) ip.getPayload();
                if (udp.getDestinationPort() == UDP.RIP_PORT) {
                    this.handleRIPPacket(etherPacket, inIface);
                    break;
                }
            }
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
        System.out.println("Incoming ARP Packet");
        ARP arpPacket = (ARP) etherPacket.getPayload();
        switch(arpPacket.getOpCode()) {
        case ARP.OP_REQUEST:
            int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
            if (targetIp == inIface.getIpAddress()) {
                sendArpReply(etherPacket, arpPacket, inIface);
            }
            break;
        case ARP.OP_REPLY:
            handleArpResponse(arpPacket);
            break;
        }
    }

    private void sendArpReply(Ethernet sourceEther, ARP sourceArp, Iface inIface) {
        System.out.println("Sending ARP Reply");
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

        dumpBinary(ether.serialize(), "ARP ");
        sendPacket(ether, inIface);
    }

    private void broadcastArpRequest(Iface outIface, int ip) {
        System.out.println("Sending ARP Request");
        Ethernet ether = new Ethernet();
        ARP arp = new ARP();
        ether.setPayload(arp);

        ether.setEtherType(Ethernet.TYPE_ARP);
        ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
        ether.setDestinationMACAddress(BROADCAST_MAC);

        arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arp.setProtocolType(ARP.PROTO_TYPE_IP);
        arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arp.setProtocolAddressLength((byte) 4);
        arp.setOpCode(ARP.OP_REQUEST);
        arp.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
        arp.setSenderProtocolAddress(outIface.getIpAddress());
        arp.setTargetHardwareAddress(ZERO_MAC);
        arp.setTargetProtocolAddress(ip);

        dumpBinary(ether.serialize(), "ARP ");
        sendPacket(ether, outIface);
    }

    private void handleArpResponse(ARP info) {
        System.out.println("ARP Response!");
        int ip = ByteBuffer.wrap(info.getSenderProtocolAddress()).getInt();
        System.out.printf("Freeing %08X\n", ip);
        synchronized (delayedSends) {
            ArpDelayedSend delayed = delayedSends.remove(ip);
            // keep this in the synchronized so that we don't race to the ARP cache
            if (delayed != null)
                delayed.register(info);
        }
    }

    private void updateArpStatus() {
        synchronized (delayedSends) {
            List<Integer> finished = new ArrayList<Integer>();
            for (Map.Entry<Integer, ArpDelayedSend> entry : delayedSends.entrySet()) {
                if (!entry.getValue().tryAgain()) {
                    finished.add(entry.getKey());
                }
            }
            for (Integer i : finished) {
                delayedSends.remove(i);
            }
        }
    }

    private void delayPacket(Iface inIface, Ethernet etherPacket, IPv4 ipPacket, int nextHop, Iface outIface) {
        System.out.println("Delay packet!");
        synchronized (delayedSends) {
            ArpDelayedSend entry = delayedSends.get(nextHop);
            if (entry == null) {
                entry = new ArpDelayedSend(nextHop, outIface);
                delayedSends.put(nextHop, entry);
            }
            entry.addPacket(inIface, etherPacket, ipPacket);
        }
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
            System.out.println(routeTable);
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
            System.out.println("Delaying - No ARP Entry");
            delayPacket(inIface, etherPacket, ipPacket, nextHop, outIface);
            //don't send ICMP here anymore
            //sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_HOST_UNREACHABLE_TYPE, ICMP_HOST_UNREACHABLE_CODE);
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
