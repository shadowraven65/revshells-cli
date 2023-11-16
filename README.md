# GoReverseShell: A Reverse Shell Command Generator and Listener Manager

## Description
GoReverseShell is a versatile tool designed for cybersecurity professionals. It generates customizable reverse shell commands, supports multiple encoding options, and manages listeners in different modes (CLI/GUI). It can handle various shell types and listeners such as Netcat, Metasploit, and pwncat. It also features automatic IP address fetching from network interfaces.  
NOTE: I have not done any other testing besides on Kali with Xfce for now and you will need to install something like xclip for the clipboard option to work. 

## Usage
```
Usage of revshells-cli:
  -L    List all available shells
  -e string
        Encoding method: base64, 2xbase64, or urlenc (default "none")
  -i string
        the IP address (default "tun0")
  -l string
        Type of listener (nc, msf, pwncat)
  -mode string
        Mode for listener (gui/cli) (default "gui")
  -p string
        the port number (default "4444")
  -r string
        Choose the reverse shell format (default "bash")
  -s string
        the shell to use (default "bash")
```

## Installation and Setup
1. Clone the repository:
   ```
   git clone https://github.com/shadowraven65/revshells-cli.git
   ```

2. Compile the program:
   ```
   go build -o revshell-cli
   ```
3. Or download the latest release and run it

## Usage
- **Generate Reverse Shell Commands:**
  ```
  ./GoReverseShell -s bash -i tun0 -p 4444 -r bash
  ```

- **Set Up Listeners (examples):**
  - **CLI will open in multiplexer where GUI will open in new terminal emulator**
  - Netcat:
    ```
    ./GoReverseShell -l nc -mode cli
    ```
  - Metasploit:
    ```
    ./GoReverseShell -l msf -mode gui
    ```
  - pwncat:
    ```
    ./GoReverseShell -l pwncat -mode cli
    ```

## Features
- **Supported Shell Types:** Bash, Telnet, Crystal, etc.
- **Encoding Options:** Base64, double Base64, URL encoding.
- **Automatic IP Address Fetching:** Fetches IP from 'tun0' or 'eth0' or defaults to localhost.

## Configuration
- Customize the `.config/revshells-cli.json` file for personal settings.
- Make sure you use {session} where in needs to go for your multiplexers session name
- Example configuration:
  ```
  {
    "gui_listener": "x-terminal-emulator -e",
    "cli_listener": "tmux new -d -s {session}",
    "custom_shells": {
      "your_custom_shell": "command_format_here"
    }
  }
  ```

## Contributing
- Contributions are welcome. Please submit pull requests or report issues for improvements.

## License
- MIT
