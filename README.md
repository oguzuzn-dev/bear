# Bear Honeypot

This project implements a basic honeypot system named "Bear," designed to mimic common services like SSH and Telnet, capturing interaction data from potential attackers. It provides a controlled environment to observe and log unauthorized access attempts and command executions.

## Features

* **SSH Honeypot**:
    * Simulates an SSH server on a configurable port (default 2222).
    * Presents a customizable SSH banner.
    * Authenticates against a list of fake usernames and passwords.
    * Logs all connection attempts, including successful and failed login attempts.
    * Supports a fake interactive shell after successful login.

* **Telnet Honeypot**:
    * Simulates a Telnet server on a configurable port (default 2323).
    * Presents a customizable Telnet banner.
    * Handles authentication with a predefined set of fake credentials.
    * Logs login attempts and provides a fake shell environment.

* **Fake Interactive Shell**:
    * Provides a convincing shell environment for logged-in users.
    * Mimics common Linux commands (`ls`, `cd`, `pwd`, `cat`, `whoami`, `ps`, `netstat`, `ifconfig`, `df`, `free`, `history`, `env`, `clear`, `exit`, `logout`).
    * Returns predefined or dynamically generated outputs for commands.
    * Logs all executed commands, marking potentially dangerous commands for easier identification.
    * Simulates a fake filesystem structure.
    * Configurable command delay to make interactions more realistic.

* **Logging System**:
    * Comprehensive logging of various events, including:
        * Connection attempts (SSH, Telnet)
        * Authentication attempts (successful/failed)
        * Command executions within the fake shell
        * Session summaries (duration, command count)
        * Security-related events (rate limiting, IP blocking, suspicious activity, multiple failed logins)
    * Logs are saved in JSON format for easy parsing and analysis.
    * Configurable log directory, level, file size, and backup count.

* **Session Management & Security**:
    * Tracks active connections and manages sessions.
    * **Rate Limiting**: Limits the number of connections per IP address within a specified time window to prevent flooding.
    * **IP Whitelisting/Blacklisting**: Allows defining specific IP addresses to be allowed or blocked.
    * Monitors and logs multiple failed login attempts.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd bear
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate # On Windows: .\venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You will need to create a `requirements.txt` file with `asyncio`, `asyncssh` if not already present.)*

4.  **Generate SSH Host Key:**
    The honeypot will automatically generate an SSH host key if one does not exist at `keys/ssh_host_key` as specified in `settings.py`.

## Configuration

All main configurations are located in `config/settings.py`.

* **SSH Settings**: Enable/disable SSH, set host, port, banner, and host key path.
* **Telnet Settings**: Enable/disable Telnet, set host, port, and banner.
* **Shell Settings**: Customize the shell prompt, hostname, initial path, command delay, and max command length.
* **Logging Settings**: Define log directory, level, file size, backup count, and format.
* **Security Settings**: Configure max login attempts, enable/disable rate limiting, set max connections per IP and time window, and define `blocked_ips` and `allowed_ips`.
* **Database Settings**: (Currently disabled) Configuration for future database integration.
* **Fake Users**: A dictionary of `username: password` pairs for authentication.
* **Fake Filesystem**: Defines the directory structure and files.
* **Fake Command Outputs**: Predefined outputs for specific commands.
* **Environment Variables**: Sets up fake environment variables for the shell.

## Usage

To start the honeypot:

```bash
python3 main.py

To test:
ssh -p <port> <username>@<ip>
telnet <ip> <port>
```

![run](https://github.com/user-attachments/assets/a0585871-3783-4ad9-bcfa-ed251f987ded)
