import cmd2
import argparse
from sambucus.lib.target import TargetConnection, TargetAuthentication
from sambucus.smb.connection import SambucusConnection

def main():
    con_params = TargetConnection()
    auth_params = TargetAuthentication()
    con = SambucusConnection(con_params, auth_params)
    con.close()

if __name__ == '__main__':
    main()
