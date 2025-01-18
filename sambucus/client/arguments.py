import logging
import argparse
from typing import Tuple
from rich_argparse import RichHelpFormatter

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target

from sambucus.lib.utils import valid_port, positive_integer
from sambucus.lib.consts import SAMBUCUS_SMB_PORT, SAMBUCUS_SMB_SESSION_TIMEOUT, SAMBUCUS_SMB_DIALECTS
from sambucus.lib.target import TargetConnection, TargetAuthentication

sambucus_parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.", formatter_class=RichHelpFormatter)
sambucus_parser.add_argument(
    '-v', '--verbosity',
    action='count',
    default=0,
    help='Increase verbosity of the program output and logic logging.'
)
sambucus_parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

connection_argument_group = sambucus_parser.add_argument_group('Connection Arguments')

connection_argument_group.add_argument(
    '--dc-ip',
    metavar="ip address",
    help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter'
)
connection_argument_group.add_argument(
    '--target-ip',
    metavar="ip address",
    help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
        'This is useful when target is the NetBIOS name and you cannot resolve it'
)
connection_argument_group.add_argument(
    '-p', '--port', 
    default=SAMBUCUS_SMB_PORT, 
    type=valid_port, 
    metavar="destination port", 
    help='Destination port to connect to SMB Server.'
)


advanced_connection_argument_group = sambucus_parser.add_argument_group('Advanced Connection Arguments')
advanced_connection_argument_group.add_argument(
    '--timeout', 
    default=SAMBUCUS_SMB_SESSION_TIMEOUT, 
    type=positive_integer, 
    metavar="seconds", 
    help='Set session timeout (in seconds) to receiving data from the SMB Server.'
)
advanced_connection_argument_group.add_argument(
    '-c', '--compression',
    action='store_true',
    default=False,
    help='Set SMB Session Compression Flags to attempt enabling transport compression (if the remote server supports it).'
)
advanced_connection_argument_group.add_argument(
    '--unicode',
    action='store_true',
    default=False,
    help='Set SMB Session Unicode Flags to attempt enabling SMB unicode support (if the remote server supports it).'
)
advanced_connection_argument_group.add_argument(
    '--dialect',
    default=None,
    choices=SAMBUCUS_SMB_DIALECTS,
    help='Select SMB Session Preferred Dialect to attempt communications with it (if the remote server supports it).'
)

authentication_argument_group = sambucus_parser.add_argument_group('Authentication Arguments')

authentication_argument_group.add_argument(
    '-H', '--hashes',
    metavar = "NTHASH or LMHASH:NTHASH",
    help='NTLM hashes, format is either a single NTHASH or both NT and LM hashes (in the following form LMHASH:NTHASH).'
)
authentication_argument_group.add_argument(
    '--no-pass',
    default=False,
    action="store_true",
    help='don\'t ask for password (useful for -K)'
)
authentication_argument_group.add_argument(
    '-K', '--kerberos',
    default=False,
    action="store_true",
    help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. '
    'If valid credentials cannot be found, it will use the ones specified in the command line.'
)
authentication_argument_group.add_argument(
    '--kdc',
    metavar='address',
    help='Specify the remote address of the KDC to be used for kerberos authentication.'
)
authentication_argument_group.add_argument(
    '-k', '--aes_key',
    metavar = "hex key",
    help='AES key to use for Kerberos Authentication (128 or 256 bits).'
)


def parse_args(arguments: argparse.Namespace) -> Tuple[TargetConnection, TargetAuthentication]:
    if arguments.verbosity > 0:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(arguments.target)

    if arguments.target_ip is None:
        arguments.target_ip = address

    if not domain:
        domain = ''

    if password == '' and username != '' and arguments.hashes is None and arguments.no_pass is False and arguments.aes_key is None:
        from getpass import getpass
        password = getpass("Password:")

    if arguments.aes_key is not None:
        arguments.kerberos = True

    lmhash = ''
    nthash = ''
    if arguments.hashes is not None:
        colons = arguments.hashes.count(':')
        if colons > 1:
            raise ValueError("Hashes must contain only one colon!")
        elif colons == 0:
            nthash = arguments.hashes
        else:
            lmhash, nthash = arguments.hashes.split(':')
    
    if arguments.dialect and arguments.dialect.isnumeric():
        arguments.dialect = int(arguments.dialect)
    
    return TargetConnection(
        remote_host=arguments.target_ip,
        remote_name=address,
        port=arguments.port,
        timeout=arguments.timeout,
        compression=arguments.compression,
        unicode=arguments.unicode,
        preferred_dialect=arguments.dialect
    ), TargetAuthentication(
        username,
        domain,
        password,
        lmhash,
        nthash,
        aes_key=arguments.aes_key,
        kdc_host=arguments.kdc,
        kerberos=arguments.kerberos
    )
