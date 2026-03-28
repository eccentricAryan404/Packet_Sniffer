package com.sniffer;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

public class PacketSniffer {

    private static final int SNAPSHOT_LEN = 65536;
    private static final int TIMEOUT_MS   = 50;

    private final PcapNetworkInterface device;
    private final String filter;
    private final int maxPackets;

    private final PacketAnalyzer analyzer = new PacketAnalyzer();
    private final PacketStats    stats    = new PacketStats();

    public PacketSniffer(PcapNetworkInterface device, String filter, int maxPackets) {
        this.device     = device;
        this.filter     = filter;
        this.maxPackets = maxPackets;
    }

    public void start() throws PcapNativeException, NotOpenException {
        System.out.printf("%nStarting capture on [%s]%n", device.getName());
        if (!filter.isEmpty()) System.out.println("Filter: " + filter);
        System.out.println("Capturing " + maxPackets + " packets...\n");
        System.out.println("─".repeat(60));

        try (PcapHandle handle = device.openLive(SNAPSHOT_LEN, PromiscuousMode.PROMISCUOUS, TIMEOUT_MS)) {

            if (!filter.isEmpty()) {
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            }

            int captured = 0;

            while (captured < maxPackets) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    if (packet != null) {
                        captured++;
                        analyzer.analyze(packet, captured, handle.getTimestamp());
                        stats.record(packet);
                    }
                } catch (PcapNativeException e) {
                    break;
                } catch (Exception e) {
                    if (e.getClass().getSimpleName().equals("EOFException")) break;
                    // TimeoutException — continue normally
                }
            }
        }

        stats.printSummary();
    }
}
