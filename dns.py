import socket
import dnslib
import time


def parse_query(questions):
    question = str(questions[0]).split()
    qname = question[0][1:len(str(question[0]))]
    qtype = question[2]
    return qname, qtype


def get_ttl(rr):
    if rr:
        answer = str(rr[0]).split()
        ttl = int(answer[1])
        return ttl
    else:
        return 0


class DNSServer:
    def __init__(self):
        self.cache = {}
        self.deserialization()
        self.dns()

    def deserialization(self):
        file = open('cache.txt', 'rb')
        d = [line.strip() for line in file]
        n = str.encode('\n', encoding='utf-8')
        s = n.join(d)
        correct_d = s.split(b'ff')
        if d:
            for i in range(0, len(correct_d) - 1, 4):
                t1 = bytes.decode(correct_d[i], encoding='utf-8')
                t2 = bytes.decode(correct_d[i + 1], encoding='utf-8')
                t = (t1, t2)
                k1 = correct_d[i + 2]
                k2 = int.from_bytes(correct_d[i + 3], byteorder='big')
                self.cache[t] = (k1, k2)
        file.close()

    def dns(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 53))
        sock.settimeout(3.0)
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            while True:
                try:
                    result, address = sock.recvfrom(1024)
                except socket.timeout:
                    continue
                packet = dnslib.DNSRecord.parse(result)
                q = parse_query(packet.questions)
                if q in self.cache:
                    sock.sendto(self.cache[q][0], address)
                else:
                    sock1.sendto(result, ('8.8.8.8', 53))
                    result1, address1 = sock1.recvfrom(1024)
                    answer = dnslib.DNSRecord.parse(result1)
                    ttl = get_ttl(answer.rr)
                    t = int(time.time())
                    if ttl != 0:
                        self.cache[q] = (result1, t + ttl)
                    else:
                        self.cache[q] = (result1, ttl)
                    sock.sendto(result1, address)
                self.check_ttl()
        except KeyboardInterrupt:
            file1 = open('cache.txt', 'wb')
            n = b'ff'
            for key in self.cache.keys():
                file1.write(str.encode(key[0], encoding='utf-8'))
                file1.write(n)
                file1.write(str.encode(key[1], encoding='utf-8'))
                file1.write(n)
                file1.write(self.cache[key][0])
                file1.write(n)
                t = self.cache[key][1]
                file1.write(int(t).to_bytes(5, byteorder='big'))
                file1.write(n)
            file1.close()

    def check_ttl(self):
        delete = []
        for key in self.cache.keys():
            t = time.time()
            if self.cache[key][1] < t and self.cache[key][1] != 0:
                delete.append(key)
        for key in delete:
            if key in self.cache:
                self.cache.pop(key)


if __name__ == '__main__':
    dns = DNSServer()
