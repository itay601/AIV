from pydantic import BaseModel
from typing import Optional , Union ,List ,Any



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

