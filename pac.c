#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include <mongoc/mongoc.h>

void process_packet(const u_char *packet, int packet_length, int packet_number, const struct timeval *timestamp);

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_number = 0;

    // Open the network interface for packet capture
    handle = pcap_open_live("wlp3s0", BUFSIZ, 1, 1000, error_buffer);

    if (handle == NULL) {
        printf("Error opening device: %s\n", error_buffer);
        return 1;
    }

    // Initialize MongoDB client
    mongoc_init();

    // Start capturing packets in a loop
    while (1) {
        packet = pcap_next(handle, &packet_header);
        if (packet != NULL) {
            process_packet(packet, packet_header.caplen, ++packet_number, &packet_header.ts);
        }
    }

    // Close the pcap handle
    pcap_close(handle);

    // Cleanup MongoDB client
    mongoc_cleanup();

    return 0;
}

void process_packet(const u_char *packet, int packet_length, int packet_number, const struct timeval *timestamp) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if the packet contains an IP header
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        // Extract IP header information
        // Source IP
        // Destination IP
        // Protocol (ip_header->ip_p)
        // Length (ip_header->ip_len)

        // Display the separation line, packet number, and time
        printf("**********************\n");
        printf("Packet %d:\n", packet_number);
        printf("Unix Timestamp: %ld.%06ld\n", (long)timestamp->tv_sec, (long)timestamp->tv_usec);
        printf("**********************\n");

        // Depending on the protocol (TCP/UDP/ICMP), extract relevant data and display
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

            // Extract TCP header information
            // Source port (ntohs(tcp_header->th_sport))
            // Destination port (ntohs(tcp_header->th_dport))
            // TCP flags (tcp_header->th_flags)

            // Initialize MongoDB client and collection
            mongoc_client_t *client;
            mongoc_collection_t *collection;
            bson_error_t error;

            // Connect to MongoDB server
            client = mongoc_client_new("mongodb://localhost:27017");
            if (!client) {
                printf("Failed to initialize MongoDB client\n");
                return;
            }

            // Get the database and collection you want to use
            collection = mongoc_client_get_collection(client, "mydb", "packets");

            // Create a BSON document with TCP packet information
            bson_t *doc = BCON_NEW("packet_number", BCON_INT32(packet_number),
                                   "timestamp", BCON_DOUBLE(timestamp->tv_sec + timestamp->tv_usec / 1000000.0),
                                   "source_ip", BCON_UTF8(inet_ntoa(ip_header->ip_src)),
                                   "destination_ip", BCON_UTF8(inet_ntoa(ip_header->ip_dst)),
                                   "protocol", BCON_UTF8("TCP"),
                                   "source_port", BCON_INT32(ntohs(tcp_header->th_sport)),
                                   "destination_port", BCON_INT32(ntohs(tcp_header->th_dport)),
                                   "flags", BCON_INT32(tcp_header->th_flags));

            // Insert the document into the collection
            if (!mongoc_collection_insert_one(collection, doc, NULL, NULL, &error)) {
                printf("Failed to insert document: %s\n", error.message);
            }

            // Release resources
            bson_destroy(doc);
            mongoc_collection_destroy(collection);
            mongoc_client_destroy(client);

            // Print other relevant information for TCP packets
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

            // Extract UDP header information
            // Source port (ntohs(udp_header->uh_sport))
            // Destination port (ntohs(udp_header->uh_dport))

            // Initialize MongoDB client and collection
            mongoc_client_t *client;
            mongoc_collection_t *collection;
            bson_error_t error;

            // Connect to MongoDB server
            client = mongoc_client_new("mongodb://localhost:27017");
            if (!client) {
                printf("Failed to initialize MongoDB client\n");
                return;
            }

            // Get the database and collection you want to use
            collection = mongoc_client_get_collection(client, "mydb", "packets");

            // Create a BSON document with UDP packet information
            bson_t *doc = BCON_NEW("packet_number", BCON_INT32(packet_number),
                                   "timestamp", BCON_DOUBLE(timestamp->tv_sec + timestamp->tv_usec / 1000000.0),
                                   "source_ip", BCON_UTF8(inet_ntoa(ip_header->ip_src)),
                                   "destination_ip", BCON_UTF8(inet_ntoa(ip_header->ip_dst)),
                                   "protocol", BCON_UTF8("UDP"),
                                   "source_port", BCON_INT32(ntohs(udp_header->uh_sport)),
                                   "destination_port", BCON_INT32(ntohs(udp_header->uh_dport)));

            // Insert the document into the collection
            if (!mongoc_collection_insert_one(collection, doc, NULL, NULL, &error)) {
                printf("Failed to insert document: %s\n", error.message);
            }

            // Release resources
            bson_destroy(doc);
            mongoc_collection_destroy(collection);
            mongoc_client_destroy(client);

            // Print other relevant information for UDP packets
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            // Handle ICMP packets
            // Print ICMP header information
        }
    }
}
// gcc -o test pac.c -lpcap $(pkg-config --cflags --libs libmongoc-1.0)
//sudo ./test
//open terminal and *  sudo systemctl start mongod   *mongosh    *show dbs   **use mydb   *db.packets.find()

//////////
