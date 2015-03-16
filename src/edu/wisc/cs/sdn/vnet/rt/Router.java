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

    private class RIPIntermittentBroadcaster extends TimerTask {
        @Override
        public void run() {
            broadcastRIPPackets(RIPv2.COMMAND_RESPONSE, null);
        }
    }

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

    private Timer updateTimer;

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
        this.updateTimer = new Timer(true);
        this.updateTimer.schedule(new ArpLookupChecker(), 1000, 1000);
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
        // add direct subnets
        for (Iface i : interfaces.values()) {
            routeTable.insert(i.getIpAddress(), 0, i.getSubnetMask(), i, 1);
        }
        broadcastRIPPackets(RIPv2.COMMAND_REQUEST, null);
        updateTimer.schedule(new RIPIntermittentBroadcaster(), 10000, 10000);
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
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

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

    // -------------------------------- RIP ------------------------------------

    private void handleRIPPacket(Ethernet ether, Iface inIface) {
        RIPv2 rip = (RIPv2) ether.getPayload().getPayload().getPayload();
        if (routeTable.updateAll(rip, inIface)) {
            // Don't ignore inIface, since it may have multiple routers on it.
            // Then again, they would have received the offending update.
            // TODO: Can we safely exclude inIface?
            broadcastRIPPackets(RIPv2.COMMAND_RESPONSE, null);
        }
        //TODO: broadcast and reply feels redundant. else if?
        if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
            replyToRIP(ether, inIface);
        }
    }

    private void broadcastRIPPackets(byte command, Iface exclude) {
        Ethernet ether = generateRIPPacket(command, RIP_ADDRESS, BROADCAST_MAC);

        // SPAM YOUR FRIENDS WITH STATUS UPDATES!!!
        for (Iface iface : interfaces.values()) {
            if (iface == exclude)
                continue;
            sendRIPPacket(ether, iface);
        }
    }

    private void replyToRIP(Ethernet source, Iface outIface) {
        IPv4 ip = (IPv4) source.getPayload();
        Ethernet out = generateRIPPacket(RIPv2.COMMAND_RESPONSE, ip.getSourceAddress(), source.getSourceMACAddress());
        sendRIPPacket(out, outIface);
    }

    private Ethernet generateRIPPacket(byte command, int destinationAddress, byte[] destinationMac) {
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
        ip.setDestinationAddress(destinationAddress);
        ip.setProtocol(IPv4.PROTOCOL_UDP);
        ether.setDestinationMACAddress(destinationMac);
        ether.setEtherType(Ethernet.TYPE_IPv4);

        return ether;
    }

    private void sendRIPPacket(Ethernet ether, Iface iface) {
        IPv4 ip = (IPv4) ether.getPayload();
        ip.setSourceAddress(iface.getIpAddress());
        ether.setSourceMACAddress(iface.getMacAddress().toBytes());
        sendPacket(ether, iface);
    }

    // --------------------------------- ARP -----------------------------------

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
            handleArpResponse(arpPacket);
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

    private void broadcastArpRequest(Iface outIface, int ip) {
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
        arp.setOpCode(ARP.OP_REPLY);
        arp.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
        arp.setSenderProtocolAddress(outIface.getIpAddress());
        arp.setTargetHardwareAddress(ZERO_MAC);
        arp.setTargetProtocolAddress(ip);

        sendPacket(ether, outIface);
    }

    private void handleArpResponse(ARP info) {
        int ip = ByteBuffer.wrap(info.getSenderProtocolAddress()).getInt();
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
        synchronized (delayedSends) {
            ArpDelayedSend entry = delayedSends.get(nextHop);
            if (entry == null) {
                entry = new ArpDelayedSend(nextHop, outIface);
                delayedSends.put(nextHop, entry);
            }
            entry.addPacket(inIface, etherPacket, ipPacket);
        }
    }

    // ---------------------------------- IPv4 ---------------------------------

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }

        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl()) {
            sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
            return;
        }

        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();

        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
                if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
                    ICMP icmpPacket = (ICMP) ipPacket.getPayload();
                    if (icmpPacket.getIcmpType() == ICMP_ECHO_REQUEST_TYPE) {
                        sendEchoResponse(inIface, etherPacket, ipPacket, icmpPacket);
                    } else {
                        System.out.println("Non-echo ICMP packet bound for interface");
                    }
                } else {
                    sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_PORT_UNREACHABLE_TYPE, ICMP_PORT_UNREACHABLE_CODE);
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
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, ICMP Destination Net Unreachable
        if (null == bestMatch) {
            sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_NET_UNREACHABLE_TYPE, ICMP_NET_UNREACHABLE_CODE);
            return;
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry) {
            delayPacket(inIface, etherPacket, ipPacket, nextHop, outIface);
            //don't send ICMP here anymore
            //sendICMPIPPacket(inIface, etherPacket, ipPacket, ICMP_HOST_UNREACHABLE_TYPE, ICMP_HOST_UNREACHABLE_CODE);
            return;
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

        this.sendPacket(etherPacket, outIface);
    }

    // ---------------------------------- ICMP ---------------------------------

    private void sendICMPIPPacket(Iface source, Ethernet etherSource, IPv4 ipSource, byte type, byte code) {
        byte[] ipBytes = ipSource.serialize();
        byte[] packetPayload = new byte[4+ipSource.getHeaderLength()+8];
        ByteBuffer payload = ByteBuffer.wrap(packetPayload);
        payload.rewind();
        payload.putInt(0); // 4 bytes of padding
        payload.put(ipBytes, 0, Math.min(ipBytes.length, ipSource.getHeaderLength() + 8));
        sendICMPPacket(source, etherSource, ipSource, type, code, packetPayload);
    }

    private void sendEchoResponse(Iface source, Ethernet etherSource, IPv4 ipSource, ICMP icmpSource) {
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
        this.sendPacket(ether, source);
    }
}
