import csv
import datetime
from fastapi import Request, HTTPException
from typing import List
import os
from models.schemas import Packet ,PacketResponse ,Process



async def process_and_save_packets(packets: List[Packet], csv_path: str = "packet_data.csv") -> PacketResponse:
    try:
        # Get all field names from Packet model
        fieldnames = [field for field in Packet.__fields__.keys()]
        
        # Create CSV file if it doesn't exist
        file_exists = os.path.exists(csv_path)
        
        with open(csv_path, mode='a', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            
            # Write header only if file is new
            if not file_exists:
                writer.writeheader()
            
            # Process and write each packet
            for packet in packets:
                # Convert packet to dict, handling datetime and special types
                packet_dict = packet.model_dump()
                
                # Convert IP addresses to strings
                for field in packet_dict:
                    if isinstance(packet_dict[field], datetime.datetime):
                        packet_dict[field] = packet_dict[field].isoformat()
                    elif hasattr(packet_dict[field], '__str__'):
                        packet_dict[field] = str(packet_dict[field])
                
                writer.writerow(packet_dict)
        
        return PacketResponse(
            success=True,
            message=f"Processed and saved {len(packets)} packets to {csv_path}",
            data=packets
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process packets: {str(e)}")




def append_process_to_csv(process: Process, csv_filepath: str ="./processes.csv") -> None:
    """
    Appends a process' details to a CSV file.
    If the CSV does not exist, it creates one and writes the header row.
    """
    # Convert the process data to a flat dictionary
    process_data = process.dict()

    # Convert datetime field to ISO formatted string if available
    if process_data.get("StartTime"):
        process_data["StartTime"] = process_data["StartTime"].format()

    # Define the CSV header order explicitly
    headers = [
        "ProcessId",
        "ProcessName",
        "SessionId",
        "StartTime",
        "CPU",
        "MemoryUsage",
        "ThreadCount",
        "HandleCount",
        "ParentProcessId",
        "ExecutablePath",
        "CommandLine",
        "Owner",
        "NetworkConnections",
        "DllList",
        "FileAccess",
        "DigitalSignature",
    ]

    # Check if the file exists to decide whether to write header
    write_header = not os.path.exists(csv_filepath)

    with open(csv_filepath, mode="a", newline='', encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers)
        if write_header:
            writer.writeheader()
        writer.writerow(process_data)        