using System;

namespace PacketsSniffer.Core.Database.Packets
{


    public class Packetss
    {
        // Primary Key
        public int Id { get; set; }

        // Layer 2: Data Link
        public string Layer2_DataLink_SourceMAC { get; set; }
        public string Layer2_DataLink_DestinationMAC { get; set; }
        public string Layer2_DataLink_EthernetType { get; set; }

        // Layer 3: Network
        public string Layer3_Network_SourceIP { get; set; }
        public string Layer3_Network_DestinationIP { get; set; }
        public string Layer3_Network_Protocol { get; set; }
        public byte Layer3_Network_TimeToLive { get; set; }

        // Layer 4: Transport
        public uint Layer4_Transport_SourcePort { get; set; }
        public uint Layer4_Transport_DestinationPort { get; set; }
        public string Layer4_Transport_TCPFlags { get; set; }
        public ulong Layer4_Transport_SequenceNumber { get; set; }
        public ulong Layer4_Transport_AcknowledgementNumber { get; set; }
        public uint Layer4_Transport_UDP_SourcePort { get; set; }
        public uint Layer4_Transport_UDP_DestinationPort { get; set; }

        // Layer 5: Session
        public string Layer5_Session_TCPState { get; set; }

        // ICMP Details
        public string Layer3_ICMP_TypeCode { get; set; }

        // DHCP Details
        public byte Layer3_DHCP_Operation { get; set; }
        public string Layer3_DHCP_ClientAddress { get; set; }
        public string Layer3_DHCP_YourAddress { get; set; }
        public string Layer3_DHCP_ServerAddress { get; set; }
        public string Layer3_DHCP_GatewayAddress { get; set; }
        public string Layer3_DHCP_MessageType { get; set; }
        public string Layer3_DHCP_TransactionId { get; set; }
        public string Layer3_DHCP_Options { get; set; }

        // Payload Details
        public uint Payload_Length { get; set; }
        public string Payload_Hex { get; set; }
        public string Payload_ASCII { get; set; }

        // Packet Metadata
        public DateTime? Packet_Timestamp { get; set; }
        public uint Packet_Length { get; set; }
    }
}
