package com.sniffer;

import org.pcap4j.packet.*;
import java.util.*;

public class PacketStats {

    private int total, tcpCount, udpCount, icmpCount, otherCount;
    private long totalBytes;
    private final Map<String, Integer> topSrcIPs = new LinkedHashMap<>();
    private final Map<String, Integer> topDstIPs = new LinkedHashMap<>();
    private final Map<Integer, Integer> topPorts  = new LinkedHashMap<>();

    public void record(org.pcap4j.packet.Packet packet) {
        total++;
        totalBytes += packet.length();

        if (packet.get(TcpPacket.class)          != null) tcpCount++;
        else if (packet.get(UdpPacket.class)     != null) udpCount++;
        else if (packet.get(IcmpV4CommonPacket.class) != null) icmpCount++;
        else otherCount++;

        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        if (ipv4 != null) {
            String src = ipv4.getHeader().getSrcAddr().getHostAddress();
            String dst = ipv4.getHeader().getDstAddr().getHostAddress();
            topSrcIPs.merge(src, 1, Integer::sum);
            topDstIPs.merge(dst, 1, Integer::sum);
        }

        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) {
            topPorts.merge(tcp.getHeader().getDstPort().valueAsInt(), 1, Integer::sum);
        }
        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) {
            topPorts.merge(udp.getHeader().getDstPort().valueAsInt(), 1, Integer::sum);
        }
    }

    public void printSummary() {
        System.out.println("\n╔══════════════════ CAPTURE SUMMARY ══════════════════╗");
        System.out.printf("  Total Packets : %d%n", total);
        System.out.printf("  Total Bytes   : %d bytes (%.2f KB)%n", totalBytes, totalBytes / 1024.0);
        System.out.printf("  TCP           : %d (%.1f%%)%n", tcpCount,  pct(tcpCount));
        System.out.printf("  UDP           : %d (%.1f%%)%n", udpCount,  pct(udpCount));
        System.out.printf("  ICMP          : %d (%.1f%%)%n", icmpCount, pct(icmpCount));
        System.out.printf("  Other         : %d (%.1f%%)%n", otherCount, pct(otherCount));

        System.out.println("\n  Top Source IPs:");
        topSrcIPs.entrySet().stream()
            .sorted(Map.Entry.<String,Integer>comparingByValue().reversed())
            .limit(5)
            .forEach(e -> System.out.printf("    %-18s %d packets%n", e.getKey(), e.getValue()));

        System.out.println("\n  Top Destination Ports:");
        topPorts.entrySet().stream()
            .sorted(Map.Entry.<Integer,Integer>comparingByValue().reversed())
            .limit(5)
            .forEach(e -> System.out.printf("    Port %-6d %d packets%n", e.getKey(), e.getValue()));

        System.out.println("╚═════════════════════════════════════════════════════╝");
    }

    private double pct(int n) {
        return total == 0 ? 0 : (n * 100.0 / total);
    }
}
