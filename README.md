# Command and Control Server and Client via Email
C&C server and client coded within Kali Linux using Python3 with smtplib and Crypto libraries. This will only work within Linux based machines.

This project was done as a project for my CSE 363: Offensive Security course at Stony Brook University. This is for the purpose of learning and not for use for malicious intent.

This project was inspired by [Gdog](https://github.com/maldevel/gdog).

A demo video is provided via [YouTube](https://www.youtube.com/watch?v=fnXHZ2OEm3Q).

## How it works
The server takes the command and creates a MIMEMultipart object which is an email accepted by smtplib. The body of the email is a JSON that contains the command name and arguments for the command. The body is then encrypted using the Crypto library's AES functionality and the email is sent to the known email address.

On startup, the client sends a checkin email to notify the server that it is active. The checkin email contains its unique ID created from the machine's UUID. The machine will then periodically check the email to see if there are any new emails directed to the machine. If there is an email, then it will decrypt the body and execute the command. After execution, it will send a response email with an encrypted body and any files if required. After a set number of checks, the client will send another checkin email to let the server know that it is still active.

## Using the C&C Server and Client
1. On the host machine, install the smtplib and Crypto libraries using any method you prefer.
2. Go to the folder containing server.py and run using the command `python3 server.py`.
3. On client machines, run the client executable.
4. On the host machine, enter the command `list` to see the list of bots available.
5. Run any command (`cmd`, `dlfc`, `uptc`) with the appropriate usage.
6. Run the commnand `resp` with the appropriate usage to get the client response.

## Usage
Commands used by the server are:
```
list 				Retrieve a list of bots in the network
resp 				Print the response of a bot's job (Usage: dlfc botid jobid)
cmd 				Execute a system command on client machine (Usage: cmd botid `command`)
dlfc 				Download a file from the client machine (Usage: dlfc botid path)
uptc 				Upload a file to the client machine (Usage: uptc botid file_path dest_path)
```
