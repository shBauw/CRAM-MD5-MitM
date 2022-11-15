import os
from signal import SIGINT
import secrets
import base64
import hmac
import random
import socket
import sys
import signal
import re
import datetime


# Visit https://edstem.org/au/courses/8961/lessons/26522/slides/196175 to get
PERSONAL_ID = '92721D'
PERSONAL_SECRET = '0af1ded29c42a43fc6490b7b690f9a3e'

# Useful regex expressions
calRegex = re.compile(
    r'(((Mon|Tue|Wed|Thu|Fri|Sat|Sun))[,]?\s[0-9]{1,2})\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s([0-9]{4})\s([0-9]{2}):([0-9]{2})(:([0-9]{2}))?\s([\+|\-][0-9]{4})\s?')
emailRegex = re.compile(
    r'([A-Za-z0-9][-A-Za-z0-9]*)(\.([A-Za-z0-9][-A-Za-z0-9]*))*@(([A-Za-z0-9](([-A-Za-z0-9]*[A-Za-z0-9]))?(\.[A-Za-z0-9](([-A-Za-z0-9]*[A-Za-z0-9]))?)+)|\[[0-9]{1,3}(\.[0-9]{1,3}){3}\])')
ipRegex = re.compile(r'[0-9]{1,3}(\.[0-9]{1,3}){3}')


# Define global info
class infoClass:
    def __init__(self):
        self.counter = 0
        self.socket = None
        self.multi = ''
        self.pid = ''

info = infoClass()

# Make sending messages easier
def send(msg):
    msg = msg + '\r\n'
    print(info.multi + "S: {}".format(msg), end='', flush=True)
    info.socket.send("{}".format(msg).encode())

# Check if email is valid
def emailCheck(email):
    if len(email) < 3:
        return False
    if email[0] != "<" or email[-1] != ">":
        return False
    else:
        email = email[1:-1]

    if re.fullmatch(emailRegex, email):
        return True
    else:
        return False

# Server
def server(s, inbox, c, addr):
    send("220 Service ready")

    flagCounter = 0
    authFlag = False
    authing = False
    dataCollecting = False
    email = []

    while True:
        data = c.recv(1024)
        # Lost connection
        if not data:
            print("S: Connection lost\r\n", flush=True, end='')
            break
        else:
            data = data.decode("ascii")
            print("C: %s" % (data), end='', flush=True)

            # Valid message sent
            if data[-2:] == '\r\n':
                # Verification
                if authing != False:
                    data = base64.b64decode(data).decode('utf-8')
                    if data == authing:
                        authFlag = True
                        send("235 Authentication successful")
                    else:
                        send("535 Authentication credentials invalid")
                    authing = False
                    continue
                # Collecting email data
                elif dataCollecting == True:
                    if data == '.\r\n':
                        dataCollecting = False
                        send("250 Requested mail action okay completed")

                        filename = inbox + '/'
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

                        continue

                    elif len(email) == 2 and data.startswith("Date: "):
                        if re.fullmatch(calRegex, data.strip()[6:]):
                            email.append(data)
                            send("354 Start mail input end <CRLF>.<CRLF>")
                            continue
                    else:
                        email.append(data)
                        send("354 Start mail input end <CRLF>.<CRLF>")
                        continue
                # Close
                elif data == 'QUIT\r\n':
                    send("221 Service closing transmission channel")
                    break
                # Greeting
                elif data.startswith('EHLO'):
                    if flagCounter == 0:
                        data = data.strip().split()
                        if len(data) == 2:
                            if re.fullmatch(ipRegex, data[1]):
                                flagCounter += 1
                                msg = "250 127.0.0.1\r\n"
                                print(info.multi + "S: {}".format(msg),
                                      end='', flush=True)
                                msg2 = "250 AUTH CRAM-MD5\r\n"
                                print(info.multi + "S: {}".format(msg2),
                                      end='', flush=True)
                                msg += msg2
                                info.socket.send("{}".format(msg).encode())
                                continue
                    else:
                        send("503 Bad sequence of commands")
                # Begin verification
                elif data == 'AUTH CRAM-MD5\r\n':
                    if authFlag == False and flagCounter == 1:
                        token = secrets.token_urlsafe(random.randint(16, 128))
                        tokenReturn = PERSONAL_ID + " " + \
                            hmac.new(PERSONAL_SECRET.encode('utf-8'),
                                     token.encode('utf-8'), 'MD5').hexdigest()
                        token64 = base64.b64encode(
                            token.encode()).decode('utf-8')
                        send("334 " + token64)
                        authing = tokenReturn
                    else:
                        send("503 Bad sequence of commands")
                    continue
                # Reset email contents
                elif data == 'RSET\r\n':
                    email = []
                    if flagCounter > 0:
                        flagCounter = 1
                    send("250 Requested mail action okay completed")
                    continue
                # Email field
                elif data.startswith("MAIL FROM:"):
                    if flagCounter == 1:
                        if emailCheck(data[10:len(data)-2]) and flagCounter == 1:
                            email.append("From: " + data[10:])
                            send("250 Requested mail action okay completed")
                            flagCounter += 1
                            continue
                    else:
                        send("503 Bad sequence of commands")
                        continue
                # Email field
                elif data.startswith("RCPT"):
                    if (flagCounter == 2 or flagCounter == 3):
                        flagCounter = 3
                        if emailCheck(data[8:len(data)-2]) and data[:8] == "RCPT TO:":
                            if len(email) == 1:
                                email.append("To: " + data[8:len(data)-2])
                            else:
                                email[1] += "," + data[8:len(data)-2]

                            send("250 Requested mail action okay completed")
                            continue
                    else:
                        send("503 Bad sequence of commands")
                        continue
                # Email field
                elif data == 'DATA\r\n':
                    if flagCounter == 3:
                        dataCollecting = True
                        send("354 Start mail input end <CRLF>.<CRLF>")
                        continue
                    else:
                        send("503 Bad sequence of commands")
                        continue
                elif data == 'NOOP\r\n':
                    send("250 Requested mail action okay completed")
                    continue

        # Use continues, goes to this only called if it doesn't work out.
        send("501 Syntax error in parameters or arguments")

    c.close()
    info.socket = None

# Create signal handler
def signal_handler(sig, frame):
    if info.socket != None:
        send('421 Service closing transmission channel\r\n')
        info.socket.close()
    else:
        print("S: SIGINT received, closing\r\n", end="", flush=True)
    sys.exit(0)


# Define signal handler
signal.signal(signal.SIGINT, signal_handler)


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
    port = ''
    inbox = ''
    for line in file:
        if line.startswith("server_port="):
            port = int(line[12:])
        elif line.startswith("inbox_path="):
            inbox = line[11:]
            if inbox[0] == "~":
                inbox = inbox[2:]
            elif inbox[0] == ".":
                inbox = "/home" + inbox[1:]
            if not os.access(inbox, os.W_OK):
                sys.exit(2)

    if (port == '' or inbox == ''):
        sys.exit(2)

    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('localhost', port))

    while True:
        # Listen
        s.listen()

        c, addr = s.accept()
        info.socket = c
        server(s, inbox, c, addr)


if __name__ == '__main__':
    main()
