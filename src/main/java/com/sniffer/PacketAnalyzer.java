package com.sniffer;

import org.pcap4j.packet.*;
import java.sql.Timestamp;

public class PacketAnalyzer {

    public void analyze(org.pcap4j.packet.Packet packet, int num, Timestamp ts) {

        System.out.printf("▶ Packet #%-4d │ %s │ %d bytes%n", num, ts, packet.length());

        // ── Ethernet ────────────────────────────────────────────
        EthernetPacket eth = packet.get(EthernetPacket.class);
        if (eth != null) {
            System.out.printf("  [ETH]  %s → %s  (type: %s)%n",
                eth.getHeader().getSrcAddr(),
                eth.getHeader().getDstAddr(),
                eth.getHeader().getType());
        }

        // ── IPv4 ─────────────────────────────────────────────────
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        if (ipv4 != null) {
            System.out.printf("  [IPv4] %s → %s  proto=%s TTL=%d%n",
                ipv4.getHeader().getSrcAddr().getHostAddress(),
                ipv4.getHeader().getDstAddr().getHostAddress(),
                ipv4.getHeader().getProtocol(),
                ipv4.getHeader().getTtlAsInt());
        }

        // ── IPv6 ─────────────────────────────────────────────────
        IpV6Packet ipv6 = packet.get(IpV6Packet.class);
        if (ipv6 != null) {
            System.out.printf("  [IPv6] %s → %s%n",
                ipv6.getHeader().getSrcAddr().getHostAddress(),
                ipv6.getHeader().getDstAddr().getHostAddress());
        }

        // ── TCP ──────────────────────────────────────────────────
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) {
            TcpPacket.TcpHeader h = tcp.getHeader();
            System.out.printf("  [TCP]  port %d → %d  seq=%d ack=%d  [%s]%n",
                h.getSrcPort().valueAsInt(),
                h.getDstPort().valueAsInt(),
                h.getSequenceNumberAsLong(),
                h.getAcknowledgmentNumberAsLong(),
                buildTcpFlags(h));
        }

        // ── UDP ──────────────────────────────────────────────────
        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) {
            System.out.printf("  [UDP]  port %d → %d  len=%d%n",
                udp.getHeader().getSrcPort().valueAsInt(),
                udp.getHeader().getDstPort().valueAsInt(),
                udp.getHeader().getLengthAsInt());
        }

        // ── ICMP ─────────────────────────────────────────────────
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        if (icmp != null) {
            System.out.printf("  [ICMP] type=%s code=%s%n",
                icmp.getHeader().getType(),
                icmp.getHeader().getCode());
        }

        // ── Payload hex preview ──────────────────────────────────
        byte[] raw = packet.getRawData();
        int preview = Math.min(raw.length, 24);
        StringBuilder hex = new StringBuilder("  [HEX] ");
        for (int i = 0; i < preview; i++) hex.append(String.format("%02X ", raw[i]));
        if (raw.length > 24) hex.append("...");
        System.out.println(hex);

        System.out.println("─".repeat(60));
    }

    private String buildTcpFlags(TcpPacket.TcpHeader h) {
        StringBuilder flags = new StringBuilder();
        if (h.getSyn()) flags.append("SYN ");
        if (h.getAck()) flags.append("ACK ");
        if (h.getFin()) flags.append("FIN ");
        if (h.getRst()) flags.append("RST ");
        if (h.getPsh()) flags.append("PSH ");
        if (h.getUrg()) flags.append("URG ");
        return flags.toString().trim().isEmpty() ? "NONE" : flags.toString().trim();
    }
}
