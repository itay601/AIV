#from typing import List
from pydantic import BaseModel, Field, conint, constr
from typing import Optional
import datetime 


class PacketResponse(BaseModel):
    success: bool
    message: str
    data: Optional[list['Packet']] = None

    class Config:
        from_attributes = True  # Previously known as orm_mode=True


class Packet(BaseModel):
    # Primary Key 
    #Id: Optional[int]  # Auto-incremented in the database, (might be miss from client)

    # Layer 2: Data Link
    Layer2_DataLink_SourceMAC: Optional[str] = None
    Layer2_DataLink_DestinationMAC: Optional[str] = None
    Layer2_DataLink_EthernetType: Optional[constr(max_length=10)] = None

    # Layer 3: Network
    Layer3_Network_SourceIP: Optional[str] = None
    Layer3_Network_DestinationIP: Optional[str] = None
    Layer3_Network_Protocol: Optional[constr(max_length=10)] = None
    Layer3_Network_TimeToLive: Optional[conint(ge=0, le=255)] = None  # TINYINT UNSIGNED

    # Layer 4: Transport
    Layer4_Transport_SourcePort: Optional[conint(ge=0)] = None  # INT UNSIGNED
    Layer4_Transport_DestinationPort: Optional[conint(ge=0)] = None  # INT UNSIGNED
    Layer4_Transport_TCPFlags: Optional[constr(max_length=50)] = None
    Layer4_Transport_SequenceNumber: Optional[conint(ge=0)] = None  # BIGINT UNSIGNED
    Layer4_Transport_AcknowledgementNumber: Optional[conint(ge=0)] = None  # BIGINT UNSIGNED
    Layer4_Transport_UDP_SourcePort: Optional[conint(ge=0)] = None  # INT UNSIGNED
    Layer4_Transport_UDP_DestinationPort: Optional[conint(ge=0)] = None  # INT UNSIGNED

    # Layer 5: Session
    Layer5_Session_TCPState: Optional[constr(max_length=50)] = None
    # SSH Detected
    SSHdetected : Optional[bool] = None
    HTTP_UserAgent : Optional[str] = None
    HTTP_Path : Optional[str] = None
    HTTP_IsPOST : Optional[bool] = None
    DNS_Query : Optional[str] = None
    DNS_RecordType : Optional[str] = None
    # ICMP Details
    Layer3_ICMP_TypeCode: Optional[constr(max_length=10)] = None

    # DHCP Details
    Layer3_DHCP_Operation: Optional[conint(ge=0, le=255)] = None  # TINYINT UNSIGNED
    Layer3_DHCP_ClientAddress: Optional[str] = None
    Layer3_DHCP_YourAddress: Optional[str] = None
    Layer3_DHCP_ServerAddress: Optional[str] = None
    Layer3_DHCP_GatewayAddress: Optional[str] = None
    Layer3_DHCP_MessageType: Optional[constr(max_length=50)] = None
    Layer3_DHCP_TransactionId: Optional[str] = None
    Layer3_DHCP_Options: Optional[str] = None  # TEXT

    # Payload Details
    Payload_Length: Optional[str] = None  # INT UNSIGNED
    Payload_Hex: Optional[str] = None  # TEXT
    Payload_ASCII: Optional[str] = None  # TEXT

    # Packet Metadata
    Packet_Timestamp: Optional[str] = None  # DATETIME, parsed as ISO 8601
    Packet_Length: Optional[str] = None  # INT UNSIGNED

    class Config:
        from_attributes = True  # Enable ORM mode
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            bytes: lambda v: v.hex()
        }



####    Processes   ####   


class Process(BaseModel):
    ProcessId: int = None
    ProcessName: str = None
    SessionId: int = None
    StartTime: Optional[str] = None
    CPU: Optional[float] = None
    MemoryUsage: int = None
    ThreadCount: Optional[int] = None
    HandleCount: Optional[int] = None
    ParentProcessId: Optional[int] = None
    ExecutablePath: Optional[str] = None
    CommandLine: Optional[str] = None
    Owner: Optional[str] = None
    NetworkConnections: Optional[list[str]] = None
    DllList: Optional[list[str]] = None
    FileAccess: Optional[list[str]] = None
    DigitalSignature: Optional[str] = None
    



class ProcessResponse(BaseModel):
    success: bool
    message: str
    data: Optional[list['Process']] = None

    class Config:
        from_attributes = True  # Previously known as orm_mode=True    