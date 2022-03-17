# SSH and FTP Honeypots

## Installation Requirements
1- Install the Paramiko library that handles the SSH server and authentication using the command:
        ```pip3 install paramiko```

2- Generate an RSA private key that will be used for the SSH pot (or use the provided one “test.pem”)

## Usage Instruction

### **SSH Pot**:
1- Run ssh_pot.py file and provide the IP address and the port you want the service to work on (default will be “localhost” and “2222”):
        
        python3 ssh_pot.py --address “IP address” --port “port number 

2- To test the connection, open a Linux terminal and use the SSH command to connect to the service and interact with it:
        
        $ssh root@localhost –p 2222

3- The shell will require a password to login which will be stored in a file. To login successfully type the password “admin123” and you will access the fake server

4- Try to pass some commands like “ ls ”, “ pwd ”, “ rm ”.

5 –The interactions with the server and connection attempts will be logged in “ssh_connections.log” and “ssh_interactions.log”

### **FTP Pot**:
1- Run the ftp_pot.py using the command (default arguments are “localhost”, “2121”):
    
        python3 ftp_pot.py --address {IP address} --port {port number} 
    
2- you can access the service using the “ftp” command such as “ftp localhost 2121”
    
3- The server will ask for username and password to authenticate. However, the client will never be able to login

4- The connections and interactions log are stored in “ftp_connections.log” and “ftp_interactions.log”