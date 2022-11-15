import os
import socket
import sys
import base64
import hmac
import re
import signal


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
        self.s = ''

info = infoClass()

# Make sending messages easier
def send(msg):
    msg = msg + '\r\n'
    print("C: {}".format(msg), end='', flush=True)
    info.s.send("{}".format(msg).encode())

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

# Send email to server
def sendToServer(email, sPort):
    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Connect to server
    try:
        s.connect(('localhost', sPort))
        info.s = s
    except:
        print("C: Cannot establish connection")
        sys.exit(3)

    # Needed flags
    authing = False
    index = 0
    rcpts = 0
    recipients = email[2].split(',')
    # Loop for sending
    while True:
        data = s.recv(1024)
        # No data recieved
        if not data:
            print("C: Connection lost", flush=True)
            sys.exit(3)
        else:
            # Decode and print data to terminal
            data = data.decode('ascii')
            data2 = data.strip().split('\r\n')
            for line in data2:
                print("S: " + line + '\r', flush=True)

            # Check that send correctly
            if data[-2:] == '\r\n':
                # In case in the middle of verification challenge
                if authing == True:
                    data = data.strip().split()
                    if len(data) == 2 and data[0] == "334":
                        challenge = base64.b64decode(data[1])
                        tokenReturn = PERSONAL_ID + " " + \
                            hmac.new(PERSONAL_SECRET.encode('utf-8'),
                                     challenge, 'MD5').hexdigest()
                        toReturn = base64.b64encode(
                            tokenReturn.encode()).decode()
                        send(toReturn)
                        authing = False
                # Greeting
                elif data == "220 Service ready\r\n":
                    send("EHLO 127.0.0.1")
                # Verification
                elif data == "250 127.0.0.1\r\n250 AUTH CRAM-MD5\r\n":
                    if "auth" in email[index].lower():
                        authing = True
                        send("AUTH CRAM-MD5")
                        index += 1
                    else:
                        index = 1
                        send("MAIL FROM:" + email[index])
                        index += 1
                # Verification without challenge
                elif data == "250 127.0.0.1\r\n":
                    index = 1
                    send("MAIL FROM:" + email[index])
                    index += 1
                # Successful challenge
                elif data == "235 Authentication successful\r\n":
                    send("MAIL FROM:" + email[index])
                    index += 1
                # Dealing with sending part of email
                elif data == "250 Requested mail action okay completed\r\n":
                    if index == 0:
                        index = 1
                        send("MAIL FROM:" + email[index])
                        index += 1
                    elif index == 2:
                        send("RCPT TO:" + recipients[rcpts])
                        if rcpts == len(recipients) - 1:
                            index += 1
                        else:
                            rcpts += 1
                    elif index == 3:
                        send("DATA")
                    elif index == len(email):
                        send("QUIT")
                # Deal with sending data
                elif data == "354 Start mail input end <CRLF>.<CRLF>\r\n":
                    if index < len(email):
                        send(email[index])
                        index += 1
                    else:
                        send(".")
                # Exit client
                elif data == "221 Service closing transmission channel\r\n" or data == "421 Service closing transmission channel\r\n":
                    break

    # Close client and reset associated socket
    s.close()
    info.s = ''


# Verify emails before sending
def verifyEmails(send):
    emails = []
    for file in sorted(os.listdir(send)):
        # Open and add to list
        f = open(os.path.join(send, file), 'r')

        email = [os.path.join(send, file)]
        for line in f:
            email.append(line.strip())

        # Check if necessary fields are contained within
        flagCount = 0

        if email[1].startswith("From: "):
            email[1] = email[1][5:].strip()
            if emailCheck(email[1]):
                flagCount += 1
        if email[2].startswith("To: "):
            email[2] = email[2][3:].strip()
            rcptsTo = email[2].split(',')
            for line in rcptsTo:
                if not emailCheck(line):
                    flagCount -= 1
            flagCount += 1
        if email[3].startswith("Date: "):
            if re.fullmatch(calRegex, email[3].strip()[6:]):
                flagCount += 1
        if email[4].startswith("Subject: "):
            flagCount += 1

        # Deal with number of flags
        if flagCount == 4:
            emails.append(email)
        else:
            print("C: " + os.path.join(send, file) +
                  ": Bad formation", flush=True)

    # Return list if all good, returns empty list if not
    return emails

# Create signal handler
def signal_handler(sig, frame):
    print("S: SIGINT received, closing\r\n", end="", flush=True)
    if info.s != '':
        info.s.close()
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
    sPort = ''
    send = 0

    for line in file:
        if line.startswith("server_port="):
            sPort = int(line[12:])
        elif line.startswith("send_path="):
            send = line[10:]
            if send[0] == "~":
                send = send[2:]
            elif send[0] == ".":
                send = "/home" + send[1:]
            if not os.access(send, os.R_OK):
                sys.exit(2)

    if (sPort == '' or send == 0):
        sys.exit(2)

    emails = verifyEmails(send)

    for email in emails:
        sendToServer(email, sPort)


if __name__ == '__main__':
    main()
