from multiprocessing.connection import Client
from array import array

address = ('localhost', 6000)
conn = Client(address, authkey='secret password')

data = conn.recv()
print("Connected : "),
print(data[0]),
print("Approved : "),
print(data[1]),
print("Accepted : "),
print(data[2]),
print("Rejected : "),
print(data[3])
total = data[0]+data[1]+data[2]+data[3]
passed = total - data[3]
print("Packet Delivery Ratio " + (passed/total)*100 + "%")

conn.close()

