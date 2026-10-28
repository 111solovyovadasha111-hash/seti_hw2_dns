import socket
import base64
import struct

b64 = "AHcBAAABAAAAAAAABWluc21hBHVyZnUCcnUAAAEAAQ=="
data = base64.b64decode(b64)


def parse_name(data, offset):
    tokens = []
    end = None
    # "длина/указатель" токен "длина" токен ...
    while True:
        length = data[offset]

        if length & 0xC0 == 0xC0: # если указатель, то старшие биты 11
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]

        if length == 0: # идентификатор конца
            if end is None:
                end = offset + 1
            return ".".join(tokens), end

        else: # обработка токена
            offset += 1
            tokens.append(data[offset:offset + length].decode("ascii"))
            offset += length

def parse_question(data, offset):
    (qname, # запрашиваемый домен, разбитый на токены, на всех итерациях одинаковый
     offset) = parse_name(data, offset)
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    return ({
        "name":qname,
        "type": qtype,
        "class": qclass},
            offset + 4)

def parse_resourse_record(data, offset):
    name, offset = parse_name(data, offset)
    (rtype, rclass,
     ttl, # время жизни
     rdlen # длина данных дальше
     ) = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    rdata = data[offset:offset + rdlen]

    if rtype == 1: #A
        value = socket.inet_ntoa(rdata)
    elif rtype == 28: #AAAA
        value = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (2, 5):# NS, CNAME
        value = parse_name(data, offset)[0]

    else:
        value = rdata

    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "data": value
    }, offset + rdlen

def parse_request(data):
    (id_, flags,
     qd, # кол-во вопросов
     an, # кол-во ответов
     ns, # кол-во авторитетных вопросов
     ar # кол-во доп записей
     ) = struct.unpack_from("!HHHHHH", data, 0)

    message = {
        "id": id_,
        # флаги:
        "qr": flags >> 15, # запрос/ответ
        "aa": (flags >> 10) & 1, # авторитетный сервер?
        "tc": (flags >> 9) & 1, # усечен ответ?
        "rd": (flags >> 8) & 1, # нужна рекурсия
        "ra": (flags >> 7) & 1, # поддержка рекурсии
        "rcode": flags & 0xF, # код ответа

        "questions": [],
        "answers": [], #
        "authority": [], # говорит, какой днс сервер отвечает за следующий домен
        "additional": [], #
    }

    offset = 12

    for _ in range(qd):
        question, offset = parse_question(data, offset)
        message["questions"].append(question)

    for section, lenght in (("answers", an), ("authority", ns), ("additional", ar)):
        for _ in range(lenght):
            rr, offset = parse_resourse_record(data, offset)
            message[section].append(rr)
    return message
print(parse_request(data))
# while True:
