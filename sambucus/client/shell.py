import cmd2
import argparse

from sambucus import io
from sambucus.smb.connection import SambucusSMBConnection

class SambucusShell(cmd2.Cmd):
    def __init__(self, connection: SambucusSMBConnection):
        super().__init__(
            # persistent_history_file=persistent_history_file, 
            # persistent_history_length=persistent_history_length, 
            allow_cli_args=False, 
            allow_redirection=False, 
            multiline_commands=False,
        )
        
        self._connection = connection
        
        # Shell Configuration
        self.prompt = ""
        self.intro = "Welcome to Sambucus! Enter 'help' or 'help -v' for help information."
    
    def default(self, statement: cmd2.Statement) -> None:
        io.console.log(f"Unrecognized command: '{statement}'")
    
    def do_exit(self, _: cmd2.Statement) -> None:
        return self.do_quit(_)
    
    def do_reconnect(self, _: cmd2.Statement) -> None:
        with io.console.status("Reconnecting Sambucus SMB Connection..."):
            self._connection.reconnect()
    
    # TODO: add parser for shares.
    def do_shares(self, args: argparse.Namespace):
        resp = self._connection.listShares()
        for share in self._connection.listShares(args.level):
            print(share)
    