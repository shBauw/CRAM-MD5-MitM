import signal
import os
import socket
import sys
import datetime

# Define global info
class infoClass:
    def __init__(self):
        # Connected to real client
        self.server = ''
        # Connected to real server
        self.client = ''

info = infoClass()


# Make sending to client easier
def sendClient(msg):
    info.server.send(msg)
    data = msg.decode('ascii').strip().split('\r\n')
    for line in data:
        print("S: " + line + '\r', flush=True)
    for line in data:
        print("AC: " + line + '\r', flush=True)


# Make sending to server easier
def sendServer(msg):
    info.client.send(msg)
    data = msg.decode("ascii")
    print("C: %s" % (data), end='', flush=True)
    print("AS: %s" % (data), end='', flush=True)


# Create signal handler
def signal_handler(sig, frame):
    print("S: SIGINT received, closing\r\n", end="", flush=True)
    if info.server != '':
        info.server.close()
    if info.client != '':
        info.client.close()
    sys.exit(0)


# Define signal handler
signal.signal(signal.SIGINT, signal_handler)


# Main eavesdropping
def eDrop(spy, sPort):
    # Create socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    info.client = client

    # Attempt to connect
    try:
        client.connect(('localhost', sPort))
    except:
        print("AS: Cannot establish connection\r")
        info.server.close()
        sys.exit(3)

    # Useful flags
    dataCollecting = False
    email = []
    authFlag = False

    # Loop for eavesdropping
    while True:
        serverData = info.client.recv(1024)
        # Receive nothing
        if not serverData:
            print("AS: Connection lost\r", flush=True)
            sys.exit(3)
        else:
            # Mostly just send back and forth unless special exceptions
            sendClient(serverData)
            serverData = serverData.decode("ascii")
            # Exit
            if serverData == "221 Service closing transmission channel\r\n":
                break
            # To do with naming file
            elif serverData == "235 Authentication successful\r\n":
                authFlag = True
            # Know to write to email
            elif dataCollecting == True:
                if serverData == "250 Requested mail action okay completed\r\n":
                    if clientData.startswith("MAIL"):
                        email.append("From: " + clientData[10:])
                    elif clientData.startswith("RCPT"):
                        if len(email) == 1:
                            email.append(
                                "To: " + clientData[8:len(clientData)-2])
                        else:
                            email[1] += "," + clientData[8:len(clientData)-2]
                    elif clientData == "RSET\r\n":
                        email = []
                    elif clientData == '.\r\n':
                        # Print to file
                        dataCollecting = False

                        filename = spy + '/'

                        if authFlag == True:
                            filename += "auth."

                        try:
                            date_format = datetime.datetime.now().astimezone().strptime(
                                email[2], "Date: %a, %d %b %Y %X %z\r\n")
                            unix_time = datetime.datetime.timestamp(
                                date_format)
                            filename += str(round(unix_time - unix_time % 1))
                        except:
                            filename += "unknown"

                        filename += ".txt"

                        f = open(filename, 'w')
                        email[1] += "\r\n"
                        if email[len(email) - 1][-2:] == "\r\n":
                            email[len(email) - 1][:-2]
                        for line in email:
                            f.write(line.strip() + "\n")

            # Same as above for other side
            clientData = info.server.recv(1024)
            if not clientData:
                print("AC: Connection lost\r", flush=True)
                sys.exit(3)
            else:
                sendServer(clientData)
                clientData = clientData.decode("ascii")
                # Know to start collecting data
                if clientData.startswith("MAIL"):
                    dataCollecting = True
                elif dataCollecting == True:
                    if serverData == "354 Start mail input end <CRLF>.<CRLF>\r\n":
                        if clientData != '.\r\n':
                            email.append(clientData)

    client.close()
    info.client = ''


def main():
    # Check for and open file
    file = []
    if len(sys.argv) != 2:
        sys.exit(1)
    else:
        try:
            f = open(sys.argv[1], 'r')
            for line in f:
                file.append(line.strip())
        except:
            sys.exit(2)

    # Check through file
    # Certain cases will fail as using absolute paths, make sure to change when testing.
    sPort = ''
    cPort = ''
    spy = ''

    for line in file:
        if line.startswith("server_port="):
            sPort = int(line[12:])
        elif line.startswith("client_port="):
            cPort = int(line[12:])
        elif line.startswith("spy_path="):
            spy = line[9:]
            if spy[0] == "~":
                spy = spy[2:]
            elif spy[0] == ".":
                spy = "/home" + spy[1:]
            if not os.access(spy, os.W_OK):
                sys.exit(2)

    if (cPort == '' or sPort == '' or spy == ''):
        sys.exit(2)

    # Client will connect to this
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', cPort))

    while True:
        # Listen
        server.listen()

        c, addr = server.accept()
        info.server = c
        eDrop(spy, sPort)
        c.close()
        info.server = ''


if __name__ == '__main__':
    main()
