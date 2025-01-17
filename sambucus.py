#!/usr/bin/env python3
#
# Summary:
#   SaMBucus - Re-Implementation of impacket's SMBClient.
#
# Author: 
#   Raz Kissos (@covertivy)

import cmd2
from sambucus.lib.target import TargetConnection, TargetAuthentication
from sambucus.smb.connection import SambucusConnection
from sambucus.client.arguments import sambucus_parser, parse_args

def main():
    target = parse_args(sambucus_parser.parse_args())
    con = SambucusConnection(target_con=target[0], target_auth=target[1])
    con.close()

if __name__ == '__main__':
    main()
