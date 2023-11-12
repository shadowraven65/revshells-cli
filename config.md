## Config File Support
The script supports the use of a json config file so you can choose what kind of terminal to use for GUI or multiplexer for cli when starting a listener.  
It also allows you to bring your own custom shells if you have any and they will append onto the main list.  
Config location is expected to be in `~/.config/revshells-cli.json`  
If you dont supply a config file it will default to x-terminal-emulator and tmux
### Examples
```
{
    "gui_listener": "x-terminal-emulator -e",
    "cli_listener": "tmux new -d -s {session}",
    "custom_shells": {
        "custom_shell": "Hello world"
    }
}
```
or 
```
{
    "gui_listener": "qterminal -e",
    "cli_listener": "screen -dmS {session}",
    "custom_shells": {
        "custom_shell": "Hello world"
    }
}
```
You need to have your multiplexer session name be `{session}` in order for the script to give it a unique name. It appends on a random string so you can start multiple without conflicts. 
