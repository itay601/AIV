import csv
import datetime
from fastapi import Request, HTTPException
from typing import List
import os
from models.schemas import Packet ,PacketResponse


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