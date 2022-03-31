# Name: Abinav Anil
# Student #: 250964140
# Course: CS3357A
# Professor: Dr. Katchabaw

# import all the good stuff that will help us throughout the asn
import selectors
import signal
import socket
import struct
import hashlib
import sys

# Initializing various variables that we will be using
from string import punctuation

MAX_STRING_SIZE = 256
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', 0))
unpacker = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
client_list = []
sel = selectors.DefaultSelector()
BUFFER_SIZE = 1024
sequence_number = 0

# Get line char by char from socket
def get_line_from_socket(sock):
    done = False
    line = ''
    char = sock.recvfrom(1024).decode()
    while not done:
        for letter in char:
            if (letter == '\r'):
                pass
            elif (letter == '\n'):
                done = True
            else:
                line = line + letter
    return line

# Handle clients exiting
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    message = 'DISCONNECT CHAT/1.0\n'
    for reg in client_list:
        data_send(message, reg[1])
    sys.exit(0)

# Search for a client with their user and return their addr
def client_search(user):
    for reg in client_list:
        if reg[0] == user:
            return reg[1]
    return None

# Search for clients using their address that you have obtained
def client_search_by_socket(addr):
    for reg in client_list:
        if reg[1] == addr:
            return reg[0]
    return None

# Add a new client to the existing client list
def client_add(user, conn, follow_terms):
    registration = (user, conn, follow_terms)
    client_list.append(registration)

# Remove a client from the client list
def client_remove(user):
    for reg in client_list:
        if reg[0] == user:
            client_list.remove(reg)
            break

# Provide server with a list of clients in the client_list
def list_clients():
    first = True
    listc = ''
    for reg in client_list:
        if first:
            listc = reg[0]
            first = False
        else:
            listc = f'{listc}, {reg[0]}'
    return listc

# Find out the topics the client is following
def client_follows(user):
    for reg in client_list:
        if reg[0] == user:
            first = True
            listc = ''
            for topic in reg[2]:
                if first:
                    listc = topic
                    first = False
                else:
                    listc = f'{listc}, {topic}'
            return listc
    return None

# If follow command is used, add that topic
def client_add_follow(user, topic):
    for reg in client_list:
        if reg[0] == user:
            if topic in reg[2]:
                return False
            else:
                reg[2].append(topic)
                return True
    return None

# If unfollow command is invoked, remove mentioned topic from list
def client_remove_follow(user, topic):
    for reg in client_list:
        if reg[0] == user:
            if topic in reg[2]:
                reg[2].remove(topic)
                return True
            else:
                return False
    return None

# Send response to client
def data_send(response, addr):
    data = response.encode()
    size = len(data)
    packet_tuple = (sequence_number, size, data)
    packet_struct = struct.Struct(f'I I {MAX_STRING_SIZE}s')
    packedData = packet_struct.pack(*packet_tuple)
    chksum = bytes(hashlib.md5(packedData).hexdigest(), encoding="UTF-8")
    packet_tuple = (sequence_number, size, data, chksum)
    UDP_packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*packet_tuple)
    sock.sendto(UDP_packet, addr)

# Read the message sent by client and check if theres any commands or if you should just post received message
def read_message(message, addr):
    if message == '':
        print('Closing connection')
        sel.unregister(sock)
        sock.close()

    else:
        user = client_search_by_socket(addr)
        words = message.split(' ')

        # Check for client disconnections.

        if words[0] == 'DISCONNECT':
            print('Disconnecting user ' + user)
            client_remove(user)

        elif (len(words) == 2) and ((words[1] == '!list') or (words[1] == '!exit') or (words[1] == '!follow?')):

            if words[1] == '!list':
                response = list_clients() + '\n'
                data_send(response, addr)

            elif words[1] == '!exit':
                print('Disconnecting user ' + user)
                response = 'DISCONNECT CHAT/1.0\n'
                data_send(response, addr)
                client_remove(user)

            elif words[1] == '!follow?':
                response = client_follows(user) + '\n'
                data_send(response, addr)

        elif (len(words) == 3) and ((words[1] == '!follow') or (words[1] == '!unfollow')):
            if words[1] == '!follow':
                topic = words[2]
                if client_add_follow(user, topic):
                    response = f'Now following {topic}\n'
                else:
                    response = f'Error:  Was already following {topic}\n'
                data_send(response, addr)

            elif words[1] == '!unfollow':
                topic = words[2]
                if topic == '@all':
                    response = 'Error:  All users must follow @all\n'
                elif topic == '@' + user:
                    response = 'Error:  Cannot unfollow yourself\n'
                elif client_remove_follow(user, topic):
                    response = f'No longer following {topic}\n'
                else:
                    response = f'Error:  Was not following {topic}\n'
                data_send(response, addr)
    
        else:
            print(f'Received message from user {user}:  ' + message)

# Make packet with acknowledge token and sequence number
def make_pkt(ACK, seq):
    ACKvalues = (ACK, seq)
    UDP_Data = struct.Struct('I I')
    packed_data = UDP_Data.pack(*ACKvalues)
    chksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
    packet_tuple = (ACK, seq, chksum)
    return packet_tuple

# Send the packet off to client with address provided
def udt_send(sndpkt, addr):
    UDP_packet_structure = struct.Struct(f'I I 32s')
    UDP_packet = UDP_packet_structure.pack(*sndpkt)
    sock.sendto(UDP_packet, addr)

# Our main function.

def main():
    signal.signal(signal.SIGINT, signal_handler)

    # Next, we loop forever waiting for packets to arrive from clients.

    print('Will wait for client connections at port ' + str(sock.getsockname()[1]))
    print('Waiting for incoming client connections ...')
    while True:

        received_packet, addr = sock.recvfrom(1024)
        UDP_packet = unpacker.unpack(received_packet)

        received_sequence = UDP_packet[0]
        received_size = UDP_packet[1]
        received_data = UDP_packet[2]
        received_checksum = UDP_packet[3]

        values = (received_sequence, received_size, received_data)
        packer = struct.Struct(f'I I {MAX_STRING_SIZE}s')
        packed_data = packer.pack(*values)
        computed_checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

        if received_checksum == computed_checksum:

            line1 = (UDP_packet[2])[:(UDP_packet[1])].decode()
            res = line1.replace(':', ' ').replace('@', ' ').split()
            user = res[0]
            str1 = ''
            line1 = line1.split('\n')

            if client_search(user) is None:
                follow_terms = [f'@{user}', '@all']
                client_add(user, addr, follow_terms)
            if res[1] == 'Register':
                print(f'Accepted connection from client address: {addr}')
                print(f'Connection to client established, waiting to receive messages from user "{user}"...')
                sndpkt = make_pkt(1, received_sequence)
                udt_send(sndpkt, addr)
            else:
                sndpkt = make_pkt(1, received_sequence)
                udt_send(sndpkt, addr)
                read_message(str1.join(line1), addr)

        else:
            print("Chksums do not match")
            if UDP_packet[1] == 0:
                values = (1, 1)
            else:
                values = (1, 0)

            UDP_Data = struct.Struct('I I')
            packed_data = UDP_Data.pack(*values)
            chksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

            # Set the sequence to opposite of what it should be
            if UDP_packet[1] == 0:
                values2 = (1, 1, chksum)
            else:
                values2 = (1, 0, chksum)

            UDP_Packet_Data = struct.Struct('I I 32s')
            UDP_packet = UDP_Packet_Data.pack(*values2)

            # Print out what's being sent and send error
            print("Sending message:", UDP_packet, "\n")
            sock.sendto(UDP_packet, addr)


if __name__ == '__main__':
    main()
