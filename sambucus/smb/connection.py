from uuid import UUID
from typing import List

from impacket import nmb
from impacket import smb, smb3, smb3structs
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, srvs

from sambucus import io
from sambucus.lib.utils import filetime_to_dt
from sambucus.lib.target import TargetConnection, TargetAuthentication
from sambucus.smb.smb3 import SambucusSMB3
from sambucus.smb.structs.shares import ShareInformation, parse_shares_enumeration_info


class SambucusSMBConnection(SMBConnection):
    def __init__(self, target_con: TargetConnection, target_auth: TargetAuthentication):
        super().__init__(
            remoteName=target_con.remote_name, 
            remoteHost=target_con.remote_host, 
            myName="DESKTOP-V1XZZQ3", # Hard Coded for now :)
            sess_port=target_con.port, 
            timeout=target_con.timeout, 
            preferredDialect=target_con.preferred_dialect,
            manualNegotiate=True
        )
        
        self._target_con: TargetConnection = target_con
        self._target_auth: TargetAuthentication = target_auth
        
        self.connect()
        self.repr_server_information()
    
    def repr_server_information(self) -> None:
        io.console.log("Target Server Information:")
        io.console.log(
            "{host} {name} (os: {sever_os}) (domain: {domain})".format(
                host=self.getRemoteHost(),
                name=self.getServerDNSHostName(),
                sever_os=f"{self.getServerOS()} Version {self.getServerOSMajor()}.{self.getServerOSMinor()}",
                domain=f"{self.getServerDomain()} / {self.getServerDNSDomainName()}",
            )
        )
        io.console.log(f"Target Server Time: {filetime_to_dt(self._SMBConnection._Connection.get('SystemTime')).isoformat(sep=' ')}")
        io.console.log(f"Target Server GUID: {UUID(bytes_le=self._SMBConnection._Connection.get('ServerGuid'))}")
    
    def connect(self) -> None:
        with io.console.status("Negotiating SMB Session with remote host...") as s:
            self.negotiateSession(
                self._preferredDialect,
                flags1=smb.SMB.FLAGS1_PATHCASELESS | smb.SMB.FLAGS1_CANONICALIZED_PATHS,
                flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY | \
                        smb.SMB.FLAGS2_NT_STATUS | \
                        smb.SMB.FLAGS2_LONG_NAMES | \
                        smb.SMB.FLAGS2_COMPRESSED if self._target_con.compression else 0 | \
                        smb.SMB.FLAGS2_UNICODE if self._target_con.unicode else 0
            )
        with io.console.status("Authenticating to Remote Server") as s:
            if self._target_auth.kerberos:
                self.kerberosLogin(
                    self._target_auth.username,
                    self._target_auth.password,
                    self._target_auth.domain,
                    self._target_auth.lmhash,
                    self._target_auth.nthash,
                    self._target_auth.aes_key,
                    self._target_auth.kdc_host,
                    self._target_auth.tgt,
                    self._target_auth.tgs,
                    self._target_auth.use_cache,
                )
            else:
                self.login(
                    self._target_auth.username,
                    self._target_auth.password,
                    self._target_auth.domain,
                    self._target_auth.lmhash,
                    self._target_auth.nthash,
                )
        if self.isGuestSession() > 0:
            io.console.log("GUEST Session Granted")
        else:
            io.console.log("USER Session Granted")
    
    def listShares(self, level: int = 1) -> List[ShareInformation]:
        """
        get a list of available shares at the connected target.

        Available Levels of Enumeration:
            0: ('Level0', LPSHARE_INFO_0_CONTAINER),
            1: ('Level1', LPSHARE_INFO_1_CONTAINER),
            2: ('Level2', LPSHARE_INFO_2_CONTAINER),
            501: ('Level501', LPSHARE_INFO_501_CONTAINER),
            502: ('Level502', LPSHARE_INFO_502_CONTAINER),
            503: ('Level503', LPSHARE_INFO_503_CONTAINER),

        :return: a list containing dict entries for each share
        :raise SessionError: if error
        """
        # Get the shares through RPC
        
        try:
            rpctransport = transport.SMBTransport(
                self.getRemoteName(), 
                self.getRemoteHost(), 
                filename=r'\srvsvc',
                smb_connection=self
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            
            resp = srvs.hNetrShareEnum(dce, level, serverName="\\\\" + self.getRemoteHost())
        except Exception as err:
            if "INVALID_LEVEL" in str(err) or "ACCESS_DENIED" in str(err):
                io.console.log(f"Could not enumerate shares with {level =}, Falling Back to level = 1!")
                resp = srvs.hNetrShareEnum(dce, 1, serverName="\\\\" + self.getRemoteHost()) # Fallback To Enum Level = 1
            else:
                io.console.log(f"Error: {str(err)}")
        finally:
            dce.disconnect()
        
        return parse_shares_enumeration_info(resp)
    
    def negotiateSession(self, preferredDialect=None,
                         flags1=smb.SMB.FLAGS1_PATHCASELESS | smb.SMB.FLAGS1_CANONICALIZED_PATHS,
                         flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES,
                         negoData='\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'):
        """
        Perform protocol negotiation

        :param string preferredDialect: the dialect desired to talk with the target server. If None is specified the highest one available will be used
        :param string flags1: the SMB FLAGS capabilities
        :param string flags2: the SMB FLAGS2 capabilities
        :param string negoData: data to be sent as part of the nego handshake

        :return: True
        :raise SessionError: if error
        """

        # If port 445 and the name sent is *SMBSERVER we're setting the name to the IP. This is to help some old
        # applications still believing
        # *SMSBSERVER will work against modern OSes. If port is NETBIOS_SESSION_PORT the user better know about i
        # *SMBSERVER's limitations
        if self._sess_port == nmb.SMB_SESSION_PORT and self._remoteName == '*SMBSERVER':
            self._remoteName = self._remoteHost
        elif self._sess_port == nmb.NETBIOS_SESSION_PORT and self._remoteName == '*SMBSERVER':
            # If remote name is *SMBSERVER let's try to query its name.. if can't be guessed, continue and hope for the best
            nb = nmb.NetBIOS()
            try:
                res = nb.getnetbiosname(self._remoteHost)
            except:
                pass
            else:
                self._remoteName = res

        if self._sess_port == nmb.NETBIOS_SESSION_PORT:
            negoData = '\x02NT LM 0.12\x00\x02SMB 2.002\x00'

        hostType = nmb.TYPE_SERVER
        if preferredDialect is None:
            # If no preferredDialect sent, we try the highest available one.
            packet = self.negotiateSessionWildcard(self._myName, self._remoteName, self._remoteHost, self._sess_port,
                                                   self._timeout, True, flags1=flags1, flags2=flags2, data=negoData)
            if packet[0:1] == b'\xfe':
                # Answer is SMB2 packet
                self._SMBConnection = SambucusSMB3(self._remoteName, self._remoteHost, self._myName, hostType,
                                                self._sess_port, self._timeout, session=self._nmbSession,
                                                negSessionResponse=smb3.SMB2Packet(packet))
            else:
                # Answer is SMB packet, sticking to SMBv1
                self._SMBConnection = smb.SMB(self._remoteName, self._remoteHost, self._myName, hostType,
                                              self._sess_port, self._timeout, session=self._nmbSession,
                                              negPacket=packet)
        else:
            if preferredDialect == smb.SMB_DIALECT:
                self._SMBConnection = smb.SMB(self._remoteName, self._remoteHost, self._myName, hostType,
                                              self._sess_port, self._timeout)
            elif preferredDialect in [smb3structs.SMB2_DIALECT_002, smb3structs.SMB2_DIALECT_21, smb3structs.SMB2_DIALECT_30, smb3structs.SMB2_DIALECT_311]:
                self._SMBConnection = SambucusSMB3(self._remoteName, self._remoteHost, self._myName, hostType,
                                                self._sess_port, self._timeout, preferredDialect=preferredDialect)
            else:
                raise Exception("Unknown dialect %s")

        # propagate flags to the smb sub-object, except for Unicode (if server supports)
        # does not affect smb3 objects
        if isinstance(self._SMBConnection, smb.SMB):
            if self._SMBConnection.get_flags()[1] & smb.SMB.FLAGS2_UNICODE:
                flags2 |= smb.SMB.FLAGS2_UNICODE
            self._SMBConnection.set_flags(flags1=flags1, flags2=flags2)

        return True