import socket, struct

from dns import dns, ROOT
from parse_message import parse_name, build_response

HOST = "127.0.0.1"
PORT = 5300

def parse_request(data):
    request_id = struct.unpack_from("!H", data, 0)[0]
    name, end = parse_name(data, 12) # с 12 байта - секция вопросов, где лежит домен (qname)
    qtype = struct.unpack_from("!H", data, end)[0] # после qname - qtype
    bytes_question = data[12:end + 4]
    return request_id, name, qtype, bytes_question

def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"сервер {HOST} запущен на порту {PORT}")
    while True:
        data, client = sock.recvfrom(4096)
        print("клиент подключился")
        request_id, name, qtype, bytes_q = parse_request(data)
        try:
            response = dns(name, ROOT, qtype)
            packet = build_response(request_id, bytes_q, response)
        except Exception:
            packet = build_response(request_id, bytes_q, {"rcode": 2, "answers": []}) # servfail
        sock.sendto(packet, client)

if __name__ == "__main__":
    server()
