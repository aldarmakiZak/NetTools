# code redesigned from source: https://github.com/ysc3839/FakeSSHServer/blob/master/FakeSSHServer.py
# TO DO 
# 
# - add comments - 
# - commands and responses - 
# - add ascii art -  
#


import logging
import socket
import sys
import threading
import paramiko
import time
import json

host_key = paramiko.RSAKey(filename='/home/zak/Desktop/vpn/vpnserver/test.pem')
paramiko.util.log_to_file("log.log")
with open("ssh_commands","r") as file:
    commands_dict = json.load(file)

print(commands_dict)

def add_logger(name, logfile):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(logfile)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

conn_logger = add_logger("Connection attempts", "connections.log")
interaction_log = add_logger("command", "interactions.log")
t0 = time.time()


class SSHpot(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.event = threading.Event()
        self.client_address = client_address

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, username, password):
        
        if password == "toor":
            conn_logger.info(f" Connection from {self.client_address} with credintials\t {username}:\t{password}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            conn_logger.info(f" Connection from {self.client_address} with credintials\t {username}:\t{password}")
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        
        return True
   
   
class SSHthread():
    
    def execute_command(self, channel, command):
        if command in commands_dict:
            print(commands_dict[command])


    def ssh_handler(self, client, addr):
        print('listener')

        connection = paramiko.Transport(client)
        connection.set_gss_host(socket.getfqdn(""))
        connection.local_version = "SSH-2.0-OPENSSH_6.6.1.1p1 Ubuntu 2ubuntu2.10"
        connection.load_server_moduli()
        connection.add_server_key(host_key)
        pot = SSHpot(addr)
        try:
            connection.start_server(server=pot)
            print("server started")
            
        except:
            print("falied to connect with ssh")
            raise Exception("ssh negotiation failed ")
        
        channel = connection.accept(20)
        
        pot.event.wait(10)
        try:    
            channel.send("Wlecome to my server")
            run = True
            while run:
                channel.send('$ ')
                command = ""
                while not command.endswith("\r"):

                    connection = channel.recv(1024)
                    channel.send(connection)
                    
                    command += connection.decode("UTF-8")    
            
                channel.send("\r\n")
                command = command.rstrip()
                print(command)
                interaction_log.info(f" {addr} sent the command: $ {command}")
                if command == "exit":
                    run = False

                elif command in commands_dict:
                    channel.send(commands_dict[command])
                    #execute_command(channel, command)
                    #channel.send("Error\n")
                else:
                    channel.send(f"Command {command} not found\n")
        except Exception as ex:
            print("error")
            print(ex)
            try:
                connection.close()
        
            except Exception as ex:
                print(ex)
        channel.close()
        print('Connection closed')


    def run_server(self):
        print('Starting ssh server')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('10.0.2.15', 22222))

        threads = []
        while True:
            try:
                sock.listen(100)
                client, addr = sock.accept()
                print("connection received from address: {}".format(addr))
            
            
            except KeyboardInterrupt:
                sys.exit(0)

            except Exception as ex:
                print(ex)

            new_client = threading.Thread(target=self.ssh_handler, args=(client, addr))
            new_client.start()


if __name__ == '__main__':
    SSHthread().run_server()