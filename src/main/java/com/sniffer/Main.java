package com.sniffer;

import org.pcap4j.core.*;
import java.util.List;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════╗");
        System.out.println("║       Java Packet Sniffer        ║");
        System.out.println("╚══════════════════════════════════╝\n");

        try {
            // Step 1: List interfaces
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

            if (interfaces == null || interfaces.isEmpty()) {
                System.err.println("No interfaces found. Run as root/Administrator.");
                return;
            }

            System.out.println("Available Interfaces:");
            for (int i = 0; i < interfaces.size(); i++) {
                PcapNetworkInterface iface = interfaces.get(i);
                System.out.printf("  [%d] %-20s %s%n", i,
                    iface.getName(),
                    iface.getDescription() != null ? iface.getDescription() : "");
            }

            // Step 2: Select interface
            Scanner scanner = new Scanner(System.in);
            System.out.print("\nSelect interface number [0]: ");
            String input = scanner.nextLine().trim();
            int ifaceIndex = input.isEmpty() ? 0 : Integer.parseInt(input);

            // Step 3: Choose filter
            System.out.println("\nCommon BPF Filters:");
            System.out.println("  tcp           - TCP packets only");
            System.out.println("  udp           - UDP packets only");
            System.out.println("  icmp          - ICMP packets only");
            System.out.println("  port 80       - HTTP traffic");
            System.out.println("  port 443      - HTTPS traffic");
            System.out.println("  host 8.8.8.8  - Specific host");
            System.out.print("\nEnter BPF filter (or press Enter for all): ");
            String filter = scanner.nextLine().trim();

            // Step 4: Packet count
            System.out.print("Number of packets to capture [50]: ");
            String countInput = scanner.nextLine().trim();
            int packetCount = countInput.isEmpty() ? 50 : Integer.parseInt(countInput);

            // Step 5: Start sniffing
            PcapNetworkInterface device = interfaces.get(ifaceIndex);
            PacketSniffer sniffer = new PacketSniffer(device, filter, packetCount);
            sniffer.start();

        } catch (PcapNativeException e) {
            System.err.println("Error: " + e.getMessage());
            System.err.println("Make sure libpcap/WinPcap/Npcap is installed and run as root.");
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
