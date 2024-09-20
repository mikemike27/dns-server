from socket import *
import glob, json

port = 53
ip = '127.0.0.1'

serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((ip, port))

def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data

    return jsonzone

zonedata = load_zones()
def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    #byte1
    QR = '1'
    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))

    AA = '1'
    TC = '0'
    RD = '0'

    #byte2
    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring) #end of the string
                break
        else:
            state = 1
            expectedlength = byte
        y += 1

    questiontype = data[y:y+2]

    return (domainparts, questiontype)

def getzone(domain):
    global zonedata

    zone_name = '.'.join(domain)

    return zonedata[zone_name]
def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'
    elif questiontype == b'\x00\05':
        qt = 'cname'

    zone = getzone(domain)

    return (zone[qt], qt, domain)

def create_question(domainname, rectype):

    #ref to RFC1035 4.1.2
    qbytes = b''

    # Question name
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    # Question type
    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')
    elif rectype == 'cname':
        qbytes += (5).to_bytes(2, byteorder='big')

    # Question class, usually IN(internet)
    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):

    #ref to RFC1035 4.1.3

    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes += bytes([0]) + bytes([1])
    elif rectype == 'cname':
        rbytes += bytes([0]) + bytes([5])

    #CLASS IN
    rbytes += bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes += bytes([0]) + bytes([4])
        
        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    elif rectype == 'cname':

        rdata = b''

        for part in recval.strip('.').split('.'):
            rdata += bytes([len(part)])
            rdata += part.encode()

        rdata += b'\x00'

        rbytes += len(rdata).to_bytes(2, byteorder='big')
        rbytes += rdata

    return rbytes
def create_response(data):

    #ref to RFC1035 4.1.1

    #DNS header
    # Transaction ID
    TransactionID = data[0:2]

    # Get the flags
    Flags = getflags(data[2:4])

    # Question Count, most of the time is 1
    QDCOUNT = b'\x00\x01'

    # Answer Count
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    # Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Additional Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    dnsbody = b''

    records, rectype, domainname = getrecs(data[12:])

    dnsquestion = create_question(domainname, rectype)

    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody

while True:
    data, addr = serverSocket.recvfrom(512)

    #parse the DNS query and generate response
    res = create_response(data)

    serverSocket.sendto(res, addr)