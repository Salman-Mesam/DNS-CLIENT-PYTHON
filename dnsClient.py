import argparse
import struct
import random
import socket
import time


def __main__():
    

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--timeout", help='Time before sending a timeout error', type=int, default=5)
    parser.add_argument("-r", "--retrynum", help='Amount of retries allowed after error', type=int, default=3)
    parser.add_argument("-p", "--port", help='Port for request', type=int, default=53)

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-mx', action="store_true",
                       default=False, dest='mx', help="Query type")
    group.add_argument('-ns', action="store_true",
                       default=False, dest='ns', help="Query type")

    parser.add_argument(dest="ipaddress", help="IP address of server")
    parser.add_argument(dest="name", help="Name of which we want to get an ip for")
    
    args= parser.parse_args()
    
    hostname = args.name
    ipaddress = args.ipaddress[1:]
    retrynum = args.retrynum
    timeout = args.timeout
    port = args.port
    qtypeName = "A"
    qtype = 1 #Type A

    if(args.ns):
        qtypeName = "NS"
        qtype = 2 #Type NS
    elif(args.mx):
        qtypeName = "MX"
        qtype = 15 #Type MX
    
    print("DNS Client sending request for", hostname)
    print("Server:", ipaddress)
    print("Request Type:", qtypeName)
    
    response = sendRequest(hostname, ipaddress, retrynum, timeout, port, qtype)
    displayResponse(response, hostname)

            
    return 0




def displayResponse(response, hostname):

    
    #ID is at offset 0 of the packet. Each value is 2 bytes away. Offset increases by 2 
    #for every value. We get a tuple so we only want the first value of the tuple. 2nd element is empty.
    resp_id = struct.unpack_from(">H", response)[0]        #ID
    flags = struct.unpack_from(">H", response, 2)[0]       #FLAGS
    qd_count = struct.unpack_from(">H", response, 4)[0]    #QDCOUNT
    an_count = struct.unpack_from(">H", response, 6)[0]    #ANCOUNT
    ns_count = struct.unpack_from(">H", response, 8)[0]    #NSCOUNT
    ar_count = struct.unpack_from(">H", response, 10)[0]   #ARCOUNT
    

    if(an_count):    
        print("***Answer Section (", an_count, "records )***")
    else:
        print("ERROR    ANSWERS NOTFOUND")
        exit(1)
    
    aa = (flags >> 10) & 1          #Shift aa bit to the least significant bit and check with AND
    if(aa):
        authority = "auth"
    else:
        authority = "nonauth"
    rcode = flags & 15              #Isolate last 4 bits
    
    if(rcode == 1):
        print("ERROR    Format error: the name server was unable to interpret the query")
        exit(1)
    elif(rcode==2):
        print("ERROR    Server failure: the name server was unable to process this query due to a problem with the name server")
        exit(1)
    elif(rcode==3):
        print("ERROR    Name error: meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist")
        exit(1)
    elif(rcode==4):
        print("ERROR    Not implemented: the name server does not support the requested kind of query")
        exit(1)
    elif(rcode==5):
        print("ERROR    Refused: the name server refuses to perform the requested operation for policy reasons")
        exit(1)
    
    
  
    currentPosition = 12    #After header, we are at offset 12
    
    #We iterate through qname and get the offset of where it ends. Add that offset
    #Along with 2 Bytes for QType and 2 Bytes for QClass
    #This is now where the Answer section starts
    currentPosition = movePointer(response, currentPosition) + 4    
    
    #For each answer, we skip name and move the offset there. We retrieve all values along
    #the way till we reach the RDATA section of an Answer. 
    for i in range(an_count):
        currentPosition = movePointer(response, currentPosition)    #Skip name, move offset

        type = struct.unpack_from('>H', response, currentPosition)[0]
        currentPosition += 4            #2 Bytes Type, 2 Bytes Class
        
        ttl = struct.unpack_from('>I', response, currentPosition)[0]
        currentPosition += 4            #4 Bytes TTL
        
        rdlength = struct.unpack_from('>H', response, currentPosition)[0]
        currentPosition += 2            #2 Bytes RDLENGTH
        
        #Depending on the type of data, get the answer in proper format and print it
        data, currentPosition, letter = getTypeData(response, currentPosition, type, rdlength)
        if(letter == "MX"):             #When answer is MX, we separate the name from the preference
            alias = data.split(",")[0]
            pref = data.split(",")[1]
            print(letter, "\t", alias, "\t", pref, "\t", ttl, "\t", authority)
        else:
            print(letter, "\t", data, "\t", ttl, "\t", authority)
            
            
            
    for i in range(ns_count):
        currentPosition = movePointer(response, currentPosition)    #Skip name, move offset
        currentPosition += 4            #2 Bytes Type, 2 Bytes Class
        currentPosition += 4            #4 Bytes TTL
        currentPosition += 2            #2 Bytes RDLENGTH
        currentPosition = movePointer(response, currentPosition)    #Skip rdata, move offset
    
    if(ar_count > 0):
        print("***Additional Section (", ar_count, "records )***")
        for i in range(ar_count):

            currentPosition = movePointer(response, currentPosition)    #Skip name, move offset

            type = struct.unpack_from('>H', response, currentPosition)[0]
            currentPosition += 4            #2 Bytes Type, 2 Bytes Class
            
            ttl = struct.unpack_from('>I', response, currentPosition)[0]
            currentPosition += 4            #4 Bytes TTL
            
            rdlength = struct.unpack_from('>H', response, currentPosition)[0]
            currentPosition += 2            #2 Bytes RDLENGTH
            
            #Depending on the type of data, get the answer in proper format and print it
            data, currentPosition, letter = getTypeData(response, currentPosition, type, rdlength)
            if(letter == "MX"):             #When answer is MX, we separate the name from the preference
                alias = data.split(",")[0]
                pref = data.split(",")[1]
                print(letter, "\t", alias, "\t", pref, "\t", ttl, "\t", authority)
            else:
                print(letter, "\t", data, "\t", ttl, "\t", authority)
    else:
        print("ADDITIONAL ANSWERS NOTFOUND")
    return 0


#Depending on the type of the answer data, we decode it and return all attributes to be printed.
def getTypeData(response, position, type, rdlength):
    value = ""
    typeLetter = ""
    if type == 1: 
        typeLetter = "IP"
        rdata = struct.unpack_from('>' + 'B' * rdlength, response, position)    #Get the RDATA IP address
        for i in rdata:                 #Iterate over the byte RDATA and translate into a string
            value += str(i) + '.'
        value = value[:-1]              #Get rid of the last extra .
        position += rdlength            #New offset will be after the length of this RDATA
    elif type == 2:
        typeLetter = "NS"
        rdata = translateValue(response, position)  #Get the name of the ns answer
        for i in rdata:     
            value += str(i.decode("utf-8"))  + '.'  #Translate the bits into string format
        value = value[:-1]                          #Ignore the last . at the end
        position += rdlength                        #Increment offset by the length of the name to continue
    elif type == 5: 
        typeLetter = "CNAME"
        rdata= translateValue(response, position)   #Get the name of the cname answer
        for i in rdata:
            value += str(i.decode("utf-8"))  + '.'  #Translate the bits into string format
        value = value[:-1]                          #Ignore the last . at the end
        position += rdlength                        #Increment offset by the length of the name to continue
    elif type == 15:
        typeLetter = "MX"
        pref = struct.unpack_from('>H', response, position)[0]  #Get the preference attribute
        position += 2                               #Update offset, (Preference is 2 Bytes)
        rdata= translateValue(response, position)   #Get the name of the mx answer
        for i in rdata:
            value += str(i.decode("utf-8"))  + '.'  #Translate the bits into string format
        value = value[:-1]                          #Ignore the last . at the end
        value += "," + str(pref)                    #Add the preference as part of the value, extracted upon return
        position += rdlength                        #Increment offset by the length of the name to continue
    else:
        print("ERROR    Not a valid response type (Not specified in Assignment)")
        exit(1)
        
    return value, position, typeLetter


#Move our offset to the appropriate location after skipping an unwanted name field
def movePointer(value, position):
    while True:
        sigBits = struct.unpack_from('>B', value, position)[0]  #Check if it is compressed via the most significant bits
        if ((sigBits & 0xC0) == 0xC0):
            position += 2               #If it is compressed, the name is simply 2 Bytes
            return position
        if ((sigBits & 0xC0) != 0x00):
            exit(1)
        position += 1                   #If not compressed, read one letter at a time and update offset
        if sigBits == 0:                #When bit is 0, we've reached the end of our name
            return position
        position += sigBits
        
        
#Translate bytes into the appropriate name string
def translateValue(response, position):
    letters = []                                             #Array of letters that will form our name
    while True:
        sigBits = struct.unpack_from('>B', response, position)[0]       #Check if it is compressed via
        if ((sigBits & 0xC0) == 0xC0):                                  #the 2 most significant bits
            #If the name is compressed, retrieve the 14-bit pointer
            reference = struct.unpack_from('>H', response, position)[0]    #16-bits name
            position += 2                                       
            isolated_reference = reference & 0x3FFF     #0x3FFF = 11111111111111, so we isolate last 14-bits                 
            return (letters + translateValue(response, isolated_reference)) #return current name and go translate the compressed part
        if ((sigBits & 0xC0) != 0x00):
            exit(1)
        #If it's not compressed, read that specific bit and add it to our array of letters.
        position += 1
        if sigBits == 0:    #When bit is 0, we've reached the end of our name
            return letters
        letters.append(*struct.unpack_from('!%ds' % sigBits, response, position))
        position += sigBits


def sendRequest(hostname, ipaddress, retrynum, timeout, port, qtype):
    
    # BUILD PACKET
    request = struct.pack(">H", random.getrandbits(16)) # ID
    request += struct.pack('>H', 256) #0000000100000000 For Flags => decimal value of 256. Based on dnsprimer pdf.
    request += struct.pack('>H', 1)  #QDCOUNT
    request += struct.pack('>H', 0)  #ANCOUNT
    request += struct.pack('>H', 0)  #NSCOUNT
    request += struct.pack('>H', 0)  #ARCOUNT

    
    substrings = hostname.split(".")   #QNAME
    for str in substrings:
        request += struct.pack(">B", len(str))  ############ADD > FOR ENDIAN
        for letter in str: 
            request += struct.pack("c", letter.encode('utf-8'))
    
    request += struct.pack(">B", 0)  # QNAME END
    request += struct.pack('>H', qtype)  #QTYPE
    request += struct.pack('>H', 1)  #QCLASS
    
    #Perform the request retrynum times
    for tryNum in range(retrynum+1):
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSocket.settimeout(timeout)
        try:
            start = time.time() #Start Time
            clientSocket.sendto(request, (ipaddress, port))
            response, respaddress = clientSocket.recvfrom(512)
            end = time.time()   #End Time
            clientSocket.close()
            interval = end-start
            print("Response received after", interval, "seconds (",tryNum, "retries )")
            break
        except socket.timeout:
                print("ERROR    Time Out Exception.")
                if(tryNum == retrynum):
                    print("ERROR    Maximum number of retries:", retrynum, "exceeded")
    
    return response



if __name__ == "__main__":
    __main__()