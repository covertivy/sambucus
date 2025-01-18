#!/usr/bin/env python3
#
# Summary:
#   SaMBucus - Re-Implementation of impacket's SMBClient.
#
# Author: 
#   Raz Kissos (@covertivy)

import cmd2
from sambucus.lib.target import TargetConnection, TargetAuthentication
from sambucus.smb.connection import SambucusSMBConnection
from sambucus.client.arguments import sambucus_parser, parse_args

def main():
    target = parse_args(sambucus_parser.parse_args())
    con = SambucusSMBConnection(target_con=target[0], target_auth=target[1])
    for share in con.listShares(0):
        print(share)
    con.close()

if __name__ == '__main__':
    main()
