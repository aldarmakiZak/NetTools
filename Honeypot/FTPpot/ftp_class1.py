import socket
import threading
import logging
import time


# function to format logs
def add_logger(name, logfile):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(logfile)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

# create logs for connections and interaction 
conn_logger = add_logger("Connection attempts", "connections.log")
interaction_log = add_logger("command", "interactions.log")

t0 = time.time()

# class to handel cilet connactions.
class FTPthread(threading.Thread):
	def __init__(self, conn, addr):
		self.conn = conn
		self.addr = addr
		# initiate a thread per connection
		threading.Thread.__init__(self)

	def run(self):
		print(f"received connection from {self.addr}")
		# send server version 
		self.conn.send('220 (vsFTPd 3.0.3)\r\n'.encode())

		try:
			while True:
				# get data from client
				command = self.conn.recv(1024).decode()
				try:
					if not command:
						break
					else:
						print(command)

					# if the client wants to login
					if "USER" in command:
						username = command[4:].strip()
						self.conn.send("331 Please specify the password.\r\n".encode())
						loggedin = True

					# to log the passord that a clients tries to send
					elif "PASS" in command and loggedin:
						password = command[4:].strip()
						print(f"login attempt from user: {username} , password {password}")

						# log the password when the client input it
						conn_logger.info(f" Connection from {self.addr} with credintials\t {username}:\t{password}") 	
						#loggedin = False
						self.conn.send("503 Login incorrect\r\n".encode())
					
					elif "QUIT" in command:
						self.conn.send("221 Goodbye.\r\n".encode())

					# the client will never log in successfully... (further developmet will be allowing the client to login and execute commands)
					else:
						# log the commands that client send
						interaction_log.info(f" host from {self.conn} sent command {command}")
						self.conn.send("530 Please login with USER and PASS.\r\n".encode())
					
				except Exception as e:
					print("error")
					print(e)

		except Exception as e:
			print(f"client {self.addr} disconnecet ")
			

# class to start the server sockets
class FTPserver(threading.Thread):
	def __init__(self,host,port):
		# socket configurations
		self.host = host
		self.port = port
		self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.my_socket.bind((host,port))
		threading.Thread.__init__(self)

	# function to start the listener and thread
	def run(self):
		self.my_socket.listen(5)
		try:
			while True:
				conn, addr = self.my_socket.accept()
				# pass the accepted connections to the client handler
				thread = FTPthread(conn, addr)
				thread.start()
				
		except KeyboardInterrupt:
			exit(1)
	
	def stop(self):
		self.my_socket.close()

if __name__=="__main__":

	serv = FTPserver("localhost",5555)
	serv.start()
