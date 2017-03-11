import socket, optparse, os, sys
from Crypto.Cipher import AES
from native import *
## AES objecr
e = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
## tcp port
port = 3454
## SECURE SDN HEADER informations
SDN_HEADER = "_SECURE_SDN_HDR_"
SDN_LEN = 16

def main():
    ## process commandline arguments
    parser = optparse.OptionParser("usage %prog -s [server ip] -f [filename]")
    parser.add_option("-f", dest="fname", type="string", help="specify the filename")
    parser.add_option("-s", dest="server", type="string", help="specify the server ip")
    (options, args) = parser.parse_args()
    server = options.server
    fpath = options.fname
    ## check for command line arguments
    if server and fpath:
        if (os.path.isfile(fpath)):
            try:
		## create tcp socket
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.setsockopt(socket.TCP_NODELAY, socket.TCP_NODELAY, 1)
                s.connect((server, port))
		## send request with SECURE SDN HEADER
                s.send(SDN_HEADER+"Request")
                permission = s.recv(1024).strip()
		## check for the permissions and SECURE SDN HEADER
                if native(permission[:SDN_LEN]) and permission[SDN_LEN:] == "Allow":
                    flist=fpath.split('/')
                    fname=flist[len(flist)-1]
		    ## create file descriptor to send the data
                    fp=open(fpath, 'rb')
                    if fp:
			## send filename with SECURE SDN HEADER
                        s.send(SDN_HEADER+fname)
                        while True:
			    try:
				## read data from the file and encode in "utf-8"
                        	data = fp.read(1008).encode('utf-8')
			    except:
				pass
                            if not data:
				print("[+] Sent : " + fname)
                                break
                            pad =  len(data)%16
			    ## pad data to encrypt
                            if pad != 0:
                                data = data + " "*(16-pad)
			    ## encrypt data
                            data = e.encrypt(data)
			    ## send encrypted data
                            if (s.send(SDN_HEADER+data)==0):
				print("Unable to connect to the Server")
                    s.close()
                            
                elif native(permission[:SDN_LEN]) and permission[SDN_LEN:] == "Reject":
                    print("[-] Unable to connect to the Server")
                    s.close()
            except Exception as ex:
                print(ex)
    else:
        print("usage %prog -s [server ip] -f [filename]")
        sys.exit()

if __name__=='__main__':
    main()
