from typing import List
from dataclasses import dataclass

from impacket.dcerpc.v5 import srvs

@dataclass
class ShareInformation:
    # Original Data from srvs.hNetrShareEnum
    level: int
    struct: object
    
    netname: str
    type: int = None
    remark: str = None
    flags: int = None
    permissions: int = None
    max_uses: int = None
    current_uses: int = None
    path: str = None
    passwd: str = None
    servername: str = None
    reserved: int = None
    security_descriptor: bytes = None


def parse_shares_enumeration_info(struct: srvs.NetrShareEnumResponse) -> List[ShareInformation]:
    level = struct['InfoStruct']['Level']
    raw_shares = struct['InfoStruct']['ShareInfo'][f'Level{level}']['Buffer']
    shares = []
    
    for share in raw_shares:
        shares.append(parse_share_info(level, share))
    
    return shares

def parse_share_info(level: int, data: srvs.SHARE_ENUM_UNION) -> ShareInformation:
    if level == 0: return parse_share_info_0(level, data)
    if level == 1: return parse_share_info_1(level, data)
    if level == 2: return parse_share_info_2(level, data)
    if level == 501: return parse_share_info_501(level, data)
    if level == 502: return parse_share_info_502(level, data)
    if level == 503: return parse_share_info_503(level, data)

def parse_share_info_0(level: int, data: srvs.SHARE_INFO_0) -> ShareInformation:
    return ShareInformation(
        level=level,
        struct=data,
        netname=data['shi0_netname'],
    )

def parse_share_info_1(level: int, data: srvs.SHARE_INFO_1) -> ShareInformation:
    return ShareInformation(
        level=level,
        struct=data,
        netname=data['shi1_netname'],
        type=data['shi1_type'],
        remark=data['shi1_remark'],
    )

def parse_share_info_2(level: int, data: srvs.SHARE_INFO_2) -> ShareInformation:
    return ShareInformation(
        level=level,
        struct=data,
        netname=data['shi2_netname'],
        type=data['shi2_type'],
        remark=data['shi2_remark'],
        permissions=data['shi2_permissions'],
        max_uses=data['shi2_max_uses'],
        current_uses=data['shi2_current_uses'],
        path=data['shi2_path'],
        passwd=data['shi2_passwd'],
    )

def parse_share_info_501(level: int, data: srvs.SHARE_INFO_501) -> ShareInformation:
    return ShareInformation(
        level=level,
        struct=data,
        netname=data['shi501_netname'],
        type=data['shi501_type'],
        remark=data['shi501_remark'],
        flags=data['shi501_flags'],
    )

def parse_share_info_502(level: int, data: srvs.SHARE_INFO_502) -> ShareInformation:
    return ShareInformation(
        level=level,
        struct=data,
        netname=data['shi502_netname'],
        type=data['shi502_type'],
        remark=data['shi502_remark'],
        permissions=data['shi502_permissions'],
        max_uses=data['shi502_max_uses'],
        current_uses=data['shi502_current_uses'],
        path=data['shi502_path'],
        passwd=data['shi502_passwd'],
        reserved=data['shi502_reserved'],
        security_descriptor=data['shi502_security_descriptor'],
    )

def parse_share_info_503(level: int, data: srvs.SHARE_INFO_503) -> ShareInformation:
    return ShareInformation(
        level=level,
        struct=data,
        netname=data['shi503_netname'],
        type=data['shi503_type'],
        remark=data['shi503_remark'],
        permissions=data['shi503_permissions'],
        max_uses=data['shi503_max_uses'],
        current_uses=data['shi503_current_uses'],
        path=data['shi503_path'],
        passwd=data['shi503_passwd'],
        servername=data['shi503_servername'],
        reserved=data['shi503_reserved'],
        security_descriptor=data['shi503_security_descriptor'],
    )
