# revshells-cli: A Reverse Shell Command Generator and Listener Manager

## Description
revshells-cli is a versatile tool designed for cybersecurity professionals. It generates customizable reverse shell commands, supports multiple encoding options, and manages listeners in different modes (CLI/GUI). It can handle various shell types and listeners such as Netcat, Metasploit, and pwncat. It also features automatic IP address fetching from network interfaces. It was inspired by revshells.com.  
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
  ./revshells-cli -s bash -i tun0 -p 4444 -r bash
  ```

- **Set Up Listeners (examples):**
  - **CLI will open in multiplexer where GUI will open in new terminal emulator**
  - Netcat:
    ```
    ./revshells-cli -l nc -mode cli
    ```
  - Metasploit:
    ```
    ./revshells-cli -l msf -mode gui
    ```
  - pwncat:
    ```
    ./revshells-cli -l pwncat -mode cli
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

## Legal Notice

This repository provides tools and scripts intended for educational and ethical use only. It is crucial to understand that any misuse of these tools and scripts for malicious or unauthorized activities is strictly prohibited and could lead to legal consequences.

### User Responsibility

- **Authorized Use Only**: These tools and scripts should only be used in environments where you have explicit permission, such as in controlled settings like CTFs (Capture The Flag competitions), authorized penetration testing, or personal testing labs.

- **Compliance with Laws**: Users must ensure that their use of these tools and scripts adheres to all applicable local, state, national, and international laws. Unauthorized access to computer systems is illegal and punishable by law.

- **No Liability for Misuse**: The creator(s) of these tools and scripts shall not be held liable for any misuse, damages, or legal consequences resulting from the use of these resources. Users are responsible for their actions and any repercussions that may arise from improper use.

- **Ethical Intent**: These tools and scripts are developed to enhance cybersecurity knowledge, bolster defensive strategies, and support ethical hacking practices. They are not intended for malicious or unethical purposes.

### Acknowledgement of Risk

By using these tools and scripts, users acknowledge the risks associated with cybersecurity practices and accept full responsibility for ensuring ethical and legal use. Misuse of these tools can result in legal action and severe penalties. Always practice responsible and ethical hacking.

## License
- MIT
