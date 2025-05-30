#from typing import List
from pydantic import BaseModel, Field, conint, constr
from typing import Optional , Union ,List ,Any
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


#############################################################
####    Processes   ####   
class Process(BaseModel):
    ProcessId: Optional[int] = None
    ProcessName: Optional[str] = None
    SessionId: Optional[int] = None
    StartTime: Optional[str] = None
    CPU: Optional[Union[float, str]] = None  # Accept string or float for CPU
    MemoryUsage: Optional[int] = None
    ThreadCount: Optional[int] = None
    HandleCount: Optional[int] = None
    ParentProcessId: Optional[int] = None
    ExecutablePath: Optional[str] = None
    CommandLine: Optional[str] = None
    Owner: Optional[str] = None
    NetworkConnections: Optional[List[str]] = None
    DllList: Optional[List[str]] = None
    FileAccess: Optional[Union[str, List[str]]] = None  # Accept either string or list
    DigitalSignature: Optional[Union[str, bool]] = None  # Accept string or boolean


class ProcessResponse(BaseModel):
    success: bool
    message: str
    data: Optional[list['Process']] = None

    class Config:
        from_attributes = True  # Previously known as orm_mode=True    

############################################################
## analyzed files
class PEFilesDeatils(BaseModel):
    sha256: Optional[str]
    label: Optional[int]
    general: Optional[dict[str, int]]
    header: Optional[dict[str, dict[str, Any]]]
    imports: Optional[dict[str, List[str]]]
    exports: Optional[List[str]]
    section: Optional[dict[str, Any]]
    histogram: Optional[List[int]]
    byteEntropy: Optional[List[int]]
    strings: dict[str, Any]  # Ensure this is using typing.Any not the built-in any

    model_config = {
        "arbitrary_types_allowed": True,
    }    

class PEFilesDeatilsResponse(BaseModel):
    success: bool
    message: str
    data: Optional[list['PEFilesDeatils']] = None

    class Config:
        from_attributes = True  # Previously known as orm_mode=True '''

