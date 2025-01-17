from impacket.smb3 import *
from impacket.smb3structs import *


class SambucusSMB3(SMB3):
    def negotiateSession(self, preferredDialect=None, negSessionResponse=None):
        # Let's store some data for later use
        self._Connection['ClientSecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED
        if self.RequireMessageSigning is True:
            self._Connection['ClientSecurityMode'] |= SMB2_NEGOTIATE_SIGNING_REQUIRED
        self._Connection['Capabilities'] = SMB2_GLOBAL_CAP_ENCRYPTION
        currentDialect = SMB2_DIALECT_WILDCARD

        # Do we have a negSessionPacket already?
        if negSessionResponse is not None:
            # Yes, let's store the dialect answered back
            negResp = SMB2Negotiate_Response(negSessionResponse['Data'])
            currentDialect = negResp['DialectRevision']

        if currentDialect == SMB2_DIALECT_WILDCARD:
            # Still don't know the chosen dialect, let's send our options

            packet = self.SMB_PACKET()
            packet['Command'] = SMB2_NEGOTIATE
            negSession = SMB2Negotiate()

            negSession['SecurityMode'] = self._Connection['ClientSecurityMode']
            negSession['Capabilities'] = self._Connection['Capabilities']
            negSession['ClientGuid'] = self.ClientGuid
            if preferredDialect is not None:
                negSession['Dialects'] = [preferredDialect]
                if preferredDialect == SMB2_DIALECT_311:
                    # Build the Contexts
                    contextData = SMB311ContextData()
                    contextData['NegotiateContextOffset'] = 64+38+2
                    contextData['NegotiateContextCount'] = 0
                    # Add an SMB2_NEGOTIATE_CONTEXT with ContextType as SMB2_PREAUTH_INTEGRITY_CAPABILITIES
                    # to the negotiate request as specified in section 2.2.3.1:
                    negotiateContext = SMB2NegotiateContext()
                    negotiateContext['ContextType'] = SMB2_PREAUTH_INTEGRITY_CAPABILITIES

                    preAuthIntegrityCapabilities = SMB2PreAuthIntegrityCapabilities()
                    preAuthIntegrityCapabilities['HashAlgorithmCount'] = 1
                    preAuthIntegrityCapabilities['SaltLength'] = 32
                    preAuthIntegrityCapabilities['HashAlgorithms'] = b'\x01\x00'
                    preAuthIntegrityCapabilities['Salt'] = ''.join([rand.choice(string.ascii_letters) for _ in
                                                                     range(preAuthIntegrityCapabilities['SaltLength'])])

                    negotiateContext['Data'] = preAuthIntegrityCapabilities.getData()
                    negotiateContext['DataLength'] = len(negotiateContext['Data'])
                    contextData['NegotiateContextCount'] += 1
                    pad = b'\xFF' * ((8 - (negotiateContext['DataLength'] % 8)) % 8)

                    # Add an SMB2_NEGOTIATE_CONTEXT with ContextType as SMB2_ENCRYPTION_CAPABILITIES
                    # to the negotiate request as specified in section 2.2.3.1 and initialize
                    # the Ciphers field with the ciphers supported by the client in the order of preference.

                    negotiateContext2 = SMB2NegotiateContext()
                    negotiateContext2['ContextType'] = SMB2_ENCRYPTION_CAPABILITIES

                    encryptionCapabilities = SMB2EncryptionCapabilities()
                    encryptionCapabilities['CipherCount'] = 1
                    encryptionCapabilities['Ciphers'] = b'\x01\x00'

                    negotiateContext2['Data'] = encryptionCapabilities.getData()
                    negotiateContext2['DataLength'] = len(negotiateContext2['Data'])
                    contextData['NegotiateContextCount'] += 1

                    negSession['ClientStartTime'] = contextData.getData()
                    negSession['Padding'] = b'\xFF\xFF'
                    # Subsequent negotiate contexts MUST appear at the first 8-byte aligned offset following the
                    # previous negotiate context.
                    negSession['NegotiateContextList'] = negotiateContext.getData() + pad + negotiateContext2.getData()

                    # Do you want to enforce encryption? Uncomment here:
                    #self._Connection['SupportsEncryption'] = True

            else:
                negSession['Dialects'] = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]
            negSession['DialectCount'] = len(negSession['Dialects'])
            packet['Data'] = negSession

            packetID = self.sendSMB(packet)
            ans = self.recvSMB(packetID)
            if ans.isValidAnswer(STATUS_SUCCESS):
                negResp = SMB2Negotiate_Response(ans['Data'])
                if negResp['DialectRevision']  == SMB2_DIALECT_311:
                    self.__UpdateConnectionPreAuthHash(ans.rawData)

        self._Connection['MaxTransactSize']   = min(0x100000,negResp['MaxTransactSize'])
        self._Connection['MaxReadSize']       = min(0x100000,negResp['MaxReadSize'])
        self._Connection['MaxWriteSize']      = min(0x100000,negResp['MaxWriteSize'])
        self._Connection['ServerGuid']        = negResp['ServerGuid']
        self._Connection['SystemTime']        = negResp['SystemTime']
        self._Connection['GSSNegotiateToken'] = negResp['Buffer']
        self._Connection['Dialect']           = negResp['DialectRevision']

        if (negResp['SecurityMode'] & SMB2_NEGOTIATE_SIGNING_REQUIRED) == SMB2_NEGOTIATE_SIGNING_REQUIRED or \
                self._Connection['Dialect'] == SMB2_DIALECT_311:
            self._Connection['RequireSigning'] = True
        if self._Connection['Dialect'] == SMB2_DIALECT_311:
            # Always Sign
            self._Connection['RequireSigning'] = True
            negContextCount = negResp['NegotiateContextCount']
            # Process the Contexts as specified in section 3.2.5.2
            if negContextCount > 0:
                self.processContextList(negContextCount, negResp['NegotiateContextList'])

        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LEASING) == SMB2_GLOBAL_CAP_LEASING:
            self._Connection['SupportsFileLeasing'] = True
        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LARGE_MTU) == SMB2_GLOBAL_CAP_LARGE_MTU:
            self._Connection['SupportsMultiCredit'] = True

        if self._Connection['Dialect'] >= SMB2_DIALECT_30:
            # Switching to the right packet format
            self.SMB_PACKET = SMB3Packet
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_DIRECTORY_LEASING) == SMB2_GLOBAL_CAP_DIRECTORY_LEASING:
                self._Connection['SupportsDirectoryLeasing'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_MULTI_CHANNEL) == SMB2_GLOBAL_CAP_MULTI_CHANNEL:
                self._Connection['SupportsMultiChannel'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES) == SMB2_GLOBAL_CAP_PERSISTENT_HANDLES:
                self._Connection['SupportsPersistentHandles'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_ENCRYPTION) == SMB2_GLOBAL_CAP_ENCRYPTION:
                self._Connection['SupportsEncryption'] = True

            self._Connection['ServerCapabilities'] = negResp['Capabilities']
            self._Connection['ServerSecurityMode'] = negResp['SecurityMode']
            
            
            
            """
            ('StructureSize','<H=65'),
        ('SecurityMode','<H=0'),
        ('DialectRevision','<H=0'),
        # SMB 3.1.1 only. Otherwise Reserved
        ('NegotiateContextCount','<H=0'),
        ('ServerGuid','16s=""'),
        ('Capabilities','<L=0'),
        ('MaxTransactSize','<L=0'),
        ('MaxReadSize','<L=0'),
        ('MaxWriteSize','<L=0'),
        ('SystemTime','<Q=0'),
        ('ServerStartTime','<Q=0'),
        ('SecurityBufferOffset','<H=0'),
        ('SecurityBufferLength','<H=0'),
        # SMB 3.1.1 only. Otherwise Reserved
        ('NegotiateContextOffset','<L=0'),
        ('_AlignPad','_-AlignPad','self["SecurityBufferOffset"] - (64 + self["StructureSize"] - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self["SecurityBufferLength"]'),
        ('Buffer',':'),
        ('_Padding','_-Padding', '0 if self["NegotiateContextOffset"] == 0 else (self["NegotiateContextOffset"] - '
                                 'self["SecurityBufferOffset"] - self["SecurityBufferLength"])'),
        ('Padding',':=""'),
        ('_NegotiateContextList','_-NegotiateContextList', '0 if self["NegotiateContextOffset"] == 0 else '
                                                           'len(self.rawData)-self["NegotiateContextOffset"]+64'),
        ('NegotiateContextList',':=""'),
        """