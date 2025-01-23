using System;

namespace PacketsSniffer.Core.Database.Packets
{
    public class Packetss
    {
        public string Layer2_DataLink_SourceMAC { get; set; }
        public string Layer2_DataLink_DestinationMAC { get; set; }
        public string Layer2_DataLink_EthernetType { get; set; }
        public string Layer3_Network_SourceIP { get; set; }
        public string Layer3_Network_DestinationIP { get; set; }
        public string Layer3_Network_Protocol { get; set; }
        public int Layer3_Network_TimeToLive { get; set; }
        public int Layer4_Transport_SourcePort { get; set; }
        public int Layer4_Transport_DestinationPort { get; set; }
        public string Layer4_Transport_TCPFlags { get; set; }
        public long Layer4_Transport_SequenceNumber { get; set; }
        public long Layer4_Transport_AcknowledgementNumber { get; set; }
        public int Layer4_Transport_UDP_SourcePort { get; set; }
        public int Layer4_Transport_UDP_DestinationPort { get; set; }
        /// <summary>
        /// ///////////////////
        /// </summary>
        public string HTTP_UserAgent { get; set; }
        public string HTTP_Path { get; set; }
        public bool HTTP_IsPOST { get; set; }
        public string DNS_Query { get; set; }
        public string DNS_RecordType { get; set; }
        /// <summary>
        /// ///////////
        /// </summary>
        public string Layer5_Session_TCPState { get; set; }
        public bool? SSHdetected { get; set; }
        public string Layer3_ICMP_TypeCode { get; set; }
        public int Layer3_DHCP_Operation { get; set; }
        public string Layer3_DHCP_ClientAddress { get; set; }
        public string Layer3_DHCP_YourAddress { get; set; }
        public string Layer3_DHCP_ServerAddress { get; set; }
        public string Layer3_DHCP_GatewayAddress { get; set; }
        public string Layer3_DHCP_MessageType { get; set; }
        public string Layer3_DHCP_TransactionId { get; set; }
        public string Layer3_DHCP_Options { get; set; }
        public string Payload_Length { get; set; }
        public string Payload_Hex { get; set; }
        public string Payload_ASCII { get; set; }
        public string Packet_Timestamp { get; set; }
        public string Packet_Length { get; set; }


        public void DisplayPacket()
        {
            if (this == null)
            {
                Console.WriteLine("this is null.");
                return;
            }

            Console.WriteLine("=== this Details ===");
            Console.WriteLine($"Layer 2 (Data Link) Source MAC: {this.Layer2_DataLink_SourceMAC}");
            Console.WriteLine($"Layer 2 (Data Link) Destination MAC: {this.Layer2_DataLink_DestinationMAC}");
            Console.WriteLine($"Layer 2 (Data Link) Ethernet Type: {this.Layer2_DataLink_EthernetType}");
            Console.WriteLine($"Layer 3 (Network) Source IP: {this.Layer3_Network_SourceIP}");
            Console.WriteLine($"Layer 3 (Network) Destination IP: {this.Layer3_Network_DestinationIP}");
            Console.WriteLine($"Layer 3 (Network) Protocol: {this.Layer3_Network_Protocol}");
            Console.WriteLine($"Layer 3 (Network) Time To Live: {this.Layer3_Network_TimeToLive}");
            Console.WriteLine($"Layer 4 (Transport) Source Port: {this.Layer4_Transport_SourcePort}");
            Console.WriteLine($"Layer 4 (Transport) Destination Port: {this.Layer4_Transport_DestinationPort}");
            Console.WriteLine($"Layer 4 (Transport) TCP Flags: {this.Layer4_Transport_TCPFlags}");
            Console.WriteLine($"Layer 4 (Transport) Sequence Number: {this.Layer4_Transport_SequenceNumber}");
            Console.WriteLine($"Layer 4 (Transport) Acknowledgement Number: {this.Layer4_Transport_AcknowledgementNumber}");
            Console.WriteLine($"Layer 4 (Transport) UDP Source Port: {this.Layer4_Transport_UDP_SourcePort}");
            Console.WriteLine($"Layer 4 (Transport) UDP Destination Port: {this.Layer4_Transport_UDP_DestinationPort}");
            Console.WriteLine($"Layer 5 (Session) TCP State: {this.Layer5_Session_TCPState}");
            Console.WriteLine($"SSH Detected: {this.SSHdetected}");
            Console.WriteLine($"HTTP_UserAgent: {this.HTTP_UserAgent}");
            Console.WriteLine($"HTTP_Path: {this.HTTP_Path}");
            Console.WriteLine($"HTTP_IsPOST: {this.HTTP_IsPOST}");
            Console.WriteLine($"DNS_Query: {this.DNS_Query}");
            Console.WriteLine($"DNS_RecordType: {this.DNS_RecordType}");
            Console.WriteLine($"Layer 3 (ICMP) Type Code: {this.Layer3_ICMP_TypeCode}");
            Console.WriteLine($"Layer 3 (DHCP) Operation: {this.Layer3_DHCP_Operation}");
            Console.WriteLine($"Layer 3 (DHCP) Client Address: {this.Layer3_DHCP_ClientAddress}");
            Console.WriteLine($"Layer 3 (DHCP) Your Address: {this.Layer3_DHCP_YourAddress}");
            Console.WriteLine($"Layer 3 (DHCP) Server Address: {this.Layer3_DHCP_ServerAddress}");
            Console.WriteLine($"Layer 3 (DHCP) Gateway Address: {this.Layer3_DHCP_GatewayAddress}");
            Console.WriteLine($"Layer 3 (DHCP) Message Type: {this.Layer3_DHCP_MessageType}");
            Console.WriteLine($"Layer 3 (DHCP) Transaction ID: {this.Layer3_DHCP_TransactionId}");
            Console.WriteLine($"Layer 3 (DHCP) Options: {this.Layer3_DHCP_Options}");
            Console.WriteLine($"Payload Length: {this.Payload_Length}");
            Console.WriteLine($"Payload Hex: {this.Payload_Hex}");
            Console.WriteLine($"Payload ASCII: {this.Payload_ASCII}");
            Console.WriteLine($"this Timestamp: {this.Packet_Timestamp}");
            Console.WriteLine($"this Length: {this.Packet_Length}");
            Console.WriteLine("=======================");

        }
    }
}
