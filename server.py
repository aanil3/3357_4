# Name: Abinav Anil
# Student #: 250964140
# Course: CS3357A
# Professor: Dr. Katchabaw

# Importing packages that will be helpful to us throughout assignment
import socket
import struct
import hashlib
import selectors
import sys
import signal
import argparse
from urllib.parse import urlparse

sequence_number = 1
rec_sequence_number = 0

# Collecting args from user to get username and server (That will contain the host and port)
parser = argparse.ArgumentParser()
parser.add_argument("user", help="user name for this user on the chat service")
parser.add_argument("server", help="URL indicating server location in form of chat://host:port")
args = parser.parse_args()

# Initializing variables that will be helpful
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
MAX_STRING_SIZE = 256
BUFFER_SIZE = 1024
unpacker = struct.Struct(f'I I 32s')
unpacker2 = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
sel = selectors.DefaultSelector()
check = True

# Checks server arg and if it is using proper format "chat://host:port, catches error otherwise
try:
    server_address = urlparse(args.server)
    if (server_address.scheme != 'chat') or (server_address.port is None) or (server_address.hostname is None):
        raise ValueError
    host = server_address.hostname
    port = server_address.port
except ValueError:
    print('Error:  Invalid server.  Enter a URL of the form:  chat://host:port')
    sys.exit(1)

# Get User
user = args.user

# Check if there is a connection error
try:
    client_socket.connect((host, port))
except ConnectionRefusedError:
    print('Error:  That host or port is not accepting connections.')
    sys.exit(1)
print("Connection to server established. Sending intro message... \nRegistration succesful. Ready for messaging!")

# Check if user is exiting out of program and send message to server to handle
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    message = f'DISCONNECT {user} CHAT/1.0\n'
    rdt_send(message)
    sys.exit(0)

# Do the prompt as required by assignment guidelines with ">" at the beginning of lines
def do_prompt(skip_line=False):
    if skip_line:
        print("")
    print("> ", end='', flush=True)

# Get line from socket char by char
def get_line_from_socket(sock):
    done = False
    line = ''
    while not done:
        data, addr = sock.recvfrom(1024)
        UDP_PacketData = unpacker.unpack(data)
        if UDP_PacketData == '\r':
            pass
        elif UDP_PacketData == '\n':
            done = True
        else:
            line = line + UDP_PacketData[2]
    return line

# Handle all incoming messages from the packet_server
def handle_message_from_server(sock, mask):
    data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
    UDP_packet = unpacker2.unpack(data)
    line1 = (UDP_packet[2])[:(UDP_packet[1])].decode()
    line1 = line1.split('\n')
    str1 = ''
    print(str1.join(line1))
    do_prompt()
    if line1[0] == "DISCONNECT CHAT/1.0":
        sys.exit(0)
    '''
    elif line1[0] == 'ATTACHMENT':
        filename = line1[1]
        sock.setblocking(True)
        print(f'Incoming file: {filename}')
        origin = get_line_from_socket(sock)
        print(origin)
        contentlength = get_line_from_socket(sock)
        print(contentlength)
        length_words = contentlength.split(' ')
        if (len(length_words) != 2) or (length_words[0] != 'Content-Length:'):
            print('Error:  Invalid attachment header')
        else:
            bytes_read = 0
            bytes_to_read = int(length_words[1])
            with open(filename, 'wb') as file_to_write:
                while bytes_read < bytes_to_read:
                    chunk = sock.recvfrom(BUFFER_SIZE)
                    bytes_read += len(chunk)
                    file_to_write.write(chunk)
        sock.setblocking(False)
        do_prompt()
        '''

# As request as per the diagram provided, udt_send creates the UDP_packet structure and sends it to the server
def udt_send(sndpkt):
    UDP_packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*sndpkt)
    client_socket.sendto(UDP_packet, (host, port))

# make_pkt uses the sequence number and data to create the packet tuple and sends it to rdt_send who can then forward it to udt send
def make_pkt(sqc_number, data):
    size = len(data)
    packet_tuple = (sqc_number, size, data)
    packet_struct = struct.Struct(f'I I {MAX_STRING_SIZE}s')
    packedData = packet_struct.pack(*packet_tuple)
    chksum = bytes(hashlib.md5(packedData).hexdigest(), encoding="UTF-8")
    packet_tuple = (sqc_number, size, data, chksum)
    return packet_tuple

# rdt_send is in charge of sending the packet, getting the incoming response packet and verifying that everything is working and nothing is corrupted
def rdt_send(message):
    global sequence_number
    global rec_sequence_number
    data = message.encode()
    if sequence_number == 0:
        sequence_number = 1
    else:
        sequence_number = 0
    sndpkt = make_pkt(sequence_number, data)
    udt_send(sndpkt)
    packet_check = True
    while packet_check:
        try:
            client_socket.settimeout(0.009)
            data, addr = client_socket.recvfrom(1024)  # buffer size is 1024 bytes
            UDP_Packet = unpacker.unpack(data)
            values = (UDP_Packet[0], UDP_Packet[1])
            packer = struct.Struct(f'I I')
            packed_data = packer.pack(*values)
            chksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

            if UDP_Packet[2] == chksum:
                if UDP_Packet[0] == 1:
                    if UDP_Packet[1] == sequence_number:
                        rec_sequence_number = UDP_Packet[1]
                    else:
                        print("wrong order")
                else:
                    print("not acknowledged")
            else:
                print("chksums dont match")
            packet_check = False

        except socket.timeout:
            print("Expired")
            udt_send(sndpkt)

# Handles all user input and forwards it to rdt_send in order to deliver to server and go through RDT protocol
def handle_keyboard_input(file, mask):
    line = sys.stdin.readline()
    message = f'@{user}: {line}'
    rdt_send(message)
    do_prompt()

# This is the main where we check if the server exists and then deal with all the select statements.
def main():
    print('Connecting to server ...')
    message = f'{user}: Register'
    try:
        rdt_send(message)
    except ConnectionRefusedError:
        print('Error:  That host or port is not accepting connections.')
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    client_socket.setblocking(False)
    sel.register(client_socket, selectors.EVENT_READ, handle_message_from_server)
    sel.register(sys.stdin, selectors.EVENT_READ, handle_keyboard_input)

    do_prompt()
    while True:
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    main()