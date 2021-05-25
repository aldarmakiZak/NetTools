# code redesigned from source: https://github.com/ysc3839/FakeSSHServer/blob/master/FakeSSHServer.py
# 
# 
#  
# 
#   
#
#


import logging
import socket
import sys
import threading
import paramiko
import time
import json
import argparse
from paramiko.channel import ChannelStderrFile

# The server encryption key
host_key = paramiko.RSAKey(filename='./test.pem')
# paramiko logs file
#paramiko.util.log_to_file("log.log")

# get the commands that the server can response to, from a json file (You can as much commands and responses as you wnat)
with open("ssh_commands","r") as file:
    commands_dict = json.load(file)

print(commands_dict)


# function to format the loggers we will be using
def add_logger(name, logfile):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(logfile)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

# create connections log and interaction log
conn_logger = add_logger("Connection attempts", "connections.log")
interaction_log = add_logger("command", "interactions.log")
t0 = time.time()


# class to handle the ssh funcionts from the parent class paramiko.ServerInterface
class SSHpot(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.event = threading.Event()
        self.client_address = client_address

    # channel requests callback funtion
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            # open a ssh session
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # get the logins from the connected clients
    def check_auth_password(self, username, password):

        # the client can access the server if he/she guess this strog password :)
        if password == "admin123":
            conn_logger.info(f" Successful connection from {self.client_address} with credintials\t {username}:\t{password}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            conn_logger.info(f" Failed connection from {self.client_address} with credintials\t {username}:\t{password}")
            return paramiko.AUTH_FAILED

    # only password authentication is allowed (for now)
    def get_allowed_auths(self, username):
        return 'password'

    #check if the client requests a shell
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    # check if the client requests a terminal
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):

        return True

# class to handle clients connections   
class SSHthread():


    def ssh_handler(self, client, addr):
        print("[] SSH Server started")

        # paramiko library connections settings
        connection = paramiko.Transport(client)
        connection.set_gss_host(socket.getfqdn(""))
        connection.local_version = "SSH-2.0-OPENSSH_6.6.1.1p1 Ubuntu 2ubuntu2.10" # ssh service name to fool the client that this is a legit service
        connection.load_server_moduli()
        connection.add_server_key(host_key)
        pot = SSHpot(addr)

        try:
            connection.start_server(server=pot)
            print("[] SSH session started")

        except:
            print("[] Falied to connect with ssh negotiation")
            raise Exception("ssh negotiation failed ")

        # accept connections from clients
        channel = connection.accept(20)
        if not channel:
            connection.close()
        # wait for authentication
        pot.event.wait(10)

        try:    
            channel.send("\r\n\nWlecome to my server\r\n")
            connected = True

            # client requests handling
            while connected:
                channel.send('$ ')
                # srint to get clients commands
                client_command = ""
                # receive the characters byte by byte
                while not client_command.endswith("\r"):

                    connection = channel.recv(1024)
                    channel.send(connection)

                    # add the letters to one sting
                    client_command += connection.decode("UTF-8")    

                channel.send("\r\n")

                client_command = client_command.rstrip() #remove white space
                interaction_log.info(f" {addr} sent the command: $ {client_command}")

                if client_command == "exit":
                    connected = False

                elif client_command in commands_dict:
                    channel.send(f"{commands_dict[client_command]}\r\n")

                else:
                    channel.send(f"Command {client_command} not found\r\n")

        except Exception as ex:
            print("[] Error")
            print(ex)
            try:
                connection.close()

            except Exception as ex:
                print(ex)


        channel.close()
        print(f"[] Connection from {addr} closed")

    # socket and thread starting handler function
    def run_server(self,address,port):
        print("[] Starting ssh server")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port)) # needs to be dinamic

        while True:
            try:
                sock.listen(100)
                client, addr = sock.accept()
                print("[] Connection received from address: {}".format(addr))


            except KeyboardInterrupt:
                sys.exit(0)

            except Exception as ex:
                print(ex)

            new_client = threading.Thread(target=self.ssh_handler, args=(client, addr))
            new_client.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FTP honeypot. Record malicious activitied ")
    parser.add_argument("--address", action="store", default="localhost",type=str, help="IP address to listen on")
    parser.add_argument("--port", action="store", default=2222,type=int, help="Port number to listen on")

    args = parser.parse_args()
    addr = args.address
    port = args.port
    #start the server
    try:
        SSHthread().run_server(addr, port)
    except Exception as e:
        print("[] Error starting the server")
        print(e)
