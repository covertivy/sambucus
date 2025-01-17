import cmd2

class SambucusShell(cmd2.Cmd):
    def __init__(self):
        super().__init__(
            persistent_history_file=persistent_history_file, 
            persistent_history_length=persistent_history_length, 
            allow_cli_args=False, 
            allow_redirection=False, 
            multiline_commands=False,
            
        )