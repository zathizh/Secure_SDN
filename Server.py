import socket, optparse, os, sys
from threading import *
from native import *
from Crypto.Cipher import AES
from multiprocessing.connection import Listener

## AES object
e = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
## tcp port
port = 3454
## SECURE SDN HEADER informations
SDN_HEADER = "_SECURE_SDN_HDR_"
SDN_LEN = 16

## statistic variables
connected=0
approved=0
accepted=0
rejected=0

address = ('localhost', 6000)
listener = Listener(address, authkey='secret password')

## handling statistics
def stats():
    global connected
    global approved
    global accepted
    global rejected
    while True:
	## handling connections
	conn = listener.accept()
	conn.send([connected, approved, accepted, rejected])
        print 'Statistics send to ', listener.last_accepted
        conn.close()


## handling receiving files
def receiver(client, addr, path):
    data = client.recv(1024).strip()
    ## check for SECURE SDN HEADER and Requests
    if native(data[:SDN_LEN]) and data[SDN_LEN:].strip() == "Request":
	## increment # of approved connections
	global approved
	approved = approved + 1
	## Allow file transfer
        client.send(SDN_HEADER+"Allow")
        data=client.recv(1024)
	## check for SECURE SDN HEADER
	if native(data[:SDN_LEN]):
	    ## increment # of accepted packets
	    global accepted
	    global rejected
	    accepted = accepted + 1
	    fname = data[SDN_LEN:]
            fpath=path+"/"+fname
	    ## create file descriptor for receiving file
            with open (fpath, 'wb') as fp:
                while True:
                    data = client.recv(1024)
                    if not data:
		        print("[+] Received : " + fname + " ")
                        break
		    ## check for SECURE SDN HEADER
                    if native(data[:SDN_LEN]):
			## increment # of accepted packets
			accepted = accepted + 1
			## decrypt encrypted data
                        data=e.decrypt(data[16:]).rstrip()
		        try:
			    ## decode data and write into file descriptor
                	    fp.write(data.decode('utf-8'))
		        except:
			    pass
		    else:
			## increment # of rejected packets
			rejected = rejected + 1
	else:
	    ## increment # of rejected packet
	    rejected = rejected + 1
	    print("[-] Invalid Connection Blocked")
    else:
	## increment # of rejected packet
	rejected = rejected + 1
	print("[-] Invalid Connection Blocked")
        client.send(SDN_HEADER+"Reject")
    client.close()
    

def main():
    ## process command line arguments
    parser = optparse.OptionParser("usage %prog -p [path of storage] -i [ip address]")
    parser.add_option("-p", dest="path", type="string", help="specify the storage path")
    parser.add_option("-i", dest="ip", type="string", help="specify the ip address")
    (options, args) = parser.parse_args()
    path = options.path
    ip = options.ip
    if ip == None:
	ip = 'localhost'
    ## invalid command line arguments
    if (path == None):
        print("usage %prog -p [path of storage] -i [ip address]")
        sys.exit()
    ## check for file directory
    elif(os.path.isdir(path)):
	path = path.rstrip("/")
	## create tcp socket
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	##s.setsockopt(socket.TCP_NODELAY, socket.TCP_NODELAY, 1)
        s.bind((ip, port))
        s.listen(5)
	## handling statistics
	print("[+] Starting Statistic Processing")
	ts=Thread(target=stats)
	ts.daemon=True
	ts.start()

        print("[+] Starting Server")
        try:
	    ## processing client threads
            while True:
                client, addr = s.accept()
                t = Thread(target=receiver, args=(client, addr, path))
                t.daemon = True
                t.start()
		## increment # of connections
		global connected
		connected = connected + 1
        except KeyboardInterrupt:
            print("\n[-] Exiting Server")
    ## invalid file directory handling
    else:
        print("Invalid Path")
        sys.exit()
        
if __name__=='__main__':
    main()
