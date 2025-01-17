from uuid import UUID

from impacket import nmb
from impacket import smb, smb3, smb3structs
from impacket.smbconnection import SMBConnection

from sambucus.io import console
from sambucus.lib.utils import filetime_to_dt
from sambucus.lib.target import TargetConnection, TargetAuthentication
from sambucus.smb.smb3 import SambucusSMB3


class SambucusConnection(SMBConnection):
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
        
        self._compression = target_con.compression
        self._unicode = target_con.unicode
        
        with console.status("Negotiating SMB Session with remote host...") as s:
            self.negotiateSession(
                self._preferredDialect,
                flags1=smb.SMB.FLAGS1_PATHCASELESS | smb.SMB.FLAGS1_CANONICALIZED_PATHS,
                flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY | \
                        smb.SMB.FLAGS2_NT_STATUS | \
                        smb.SMB.FLAGS2_LONG_NAMES | \
                        smb.SMB.FLAGS2_COMPRESSED if self._compression else 0 | \
                        smb.SMB.FLAGS2_UNICODE if self._unicode else 0
            )
        with console.status("Authenticating to Remote Server") as s:
            if target_auth.kerberos:
                self.kerberosLogin(
                    target_auth.username,
                    target_auth.password,
                    target_auth.domain,
                    target_auth.lmhash,
                    target_auth.nthash,
                    target_auth.aesKey,
                    target_auth.kdc_host,
                    target_auth.tgt,
                    target_auth.tgs,
                    target_auth.useCache,
                )
            else:
                self.login(
                    target_auth.username,
                    target_auth.password,
                    target_auth.domain,
                    target_auth.lmhash,
                    target_auth.nthash,
                )
        if self.isGuestSession() > 0:
            console.log("GUEST Session Granted")
        else:
            console.log("USER Session Granted")
        
        
        console.log("Target Server Information:")
        console.log(
            "{host} {name} (os: {sever_os}) (domain: {domain})".format(
                host=self.getRemoteHost(),
                name=self.getServerDNSHostName(),
                sever_os=f"{self.getServerOS()} Version {self.getServerOSMajor()}.{self.getServerOSMinor()}",
                domain=f"{self.getServerDomain()} / {self.getServerDNSDomainName()}",
            )
        )
        console.log(f"Target Server Time: {filetime_to_dt(self._SMBConnection._Connection.get('SystemTime')).isoformat(sep=' ')}")
        console.log(f"Target Server GUID: {UUID(bytes_le=self._SMBConnection._Connection.get('ServerGuid'))}")
    
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
                self._SMBConnection = smb3.SambucusSMB3(self._remoteName, self._remoteHost, self._myName, hostType,
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