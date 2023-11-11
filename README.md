# revshells-cli
Go based reverse shell generator for CLI

```
Usage of revshells:
  -L    List all available shells
  -e string
        Encoding method: base64, 2xbase64, or urlenc (default "none")
  -i string
        the IP address (default "tun0")
  -l string
        Type of listener (nc, msf, pwncat)
  -p string
        the port number (default "4444")
  -r string
        Choose the reverse shell format (default "bash")
  -s string
        the shell to use (default "bash")
```
This code was created for Kali specifically to speed up rev shells for HTB and then turned into this
