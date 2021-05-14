#TO DO 
# - add logging -
# - add comments - 
# - commands and responses - 
# - add ascii art -  
#


import logging
import socket
import sys
import threading
import paramiko


host_key = paramiko.RSAKey(filename='/home/zak/Desktop/vpn/vpnserver/test.pem')
paramiko.util.log_to_file("log.log")


class SSHpot(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, username, password):
        
        if password == "toor":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        
        return True
   

def ssh_handler(client, addr):
    print('listener')


    connection = paramiko.Transport(client)
    connection.set_gss_host(socket.getfqdn(""))
    connection.local_version = "SSH-2.0-OPENSSH_6.6.1.1p1 Ubuntu 2ubuntu2.10"
    connection.load_server_moduli()
    connection.add_server_key(host_key)
    pot = SSHpot()
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
            if command == "exit":
                run = False

            else:
                channel.send("Error\n")
        
    except Exception as ex:
        print("error")
        print(ex)
        try:
            connection.close()
    
        except Exception as ex:
            print(ex)
    channel.close()
    print('Connection closed')


def run_server():
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

        new_client = threading.Thread(target=ssh_handler, args=(client, addr))
        new_client.start()
        threads.append(new_client)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    run_server()