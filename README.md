# sambucus

A Better Implementation of the notorious `impacket-smbclient` - revived with rich 🤑

## Ratinal and Mitivation

Have you ever wondered "why the hell does impacket's smbclient not have a reconnect command?"?  
Or better yet, "why the fuck can't I resume an interrupted download/upload operation?"?  
All of this and more has been my inspiration to create a better, more comfortable smbclient.  

## Goals

- Improve comfort and ease of use - UI/UX stuff.
    - Progress Bars (😱) for download and upload operations.
- Extend impacket's unimplemented and limited functionality.
    - Allows the user to utilize the full power and potential of SMB and it's complementary features.
- Add verbosity and information gathering capabilities.
    - Show remote server's system time on connection.
    - Show extended share enumeration information.
    - Implement an "SMB only" systeminfo command.
    - And much, much more...

