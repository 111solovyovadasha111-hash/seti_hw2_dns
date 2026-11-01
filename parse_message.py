import base64
import struct
import socket


def encode_name(name):
    out = b""
    for token in name.rstrip(".").split("."):
        out += bytes([len(token)]) + token.encode("ascii")
    return out + b"\x00"


def encode_resourse_record(rr):
    out = encode_name(rr["name"])
    if rr["type"] == 1:
        rdata = socket.inet_aton(rr["data"])
    elif rr["type"] == 28:
        rdata = socket.inet_pton(socket.AF_INET6, rr["data"])
    elif rr["type"] in (2, 5):
        rdata = encode_name(rr["data"])
    elif rr["type"] == 15: # тип mx, запись вида: приоритет + имя хоста почты
        rdata = struct.pack("!H", rr["data"][0]) + encode_name(rr["data"][1])
    elif rr["type"] == 16: # тип txt для каждой строки инфа + она сама
        rdata = b"".join(bytes([len(s.encode())]) + s.encode() for s in rr["data"])
    else:
        raise ValueError("тип не поддерживается")
    return out + struct.pack("!HHIH", rr["type"], rr["class"], rr["ttl"], len(rdata)) + rdata



def build_response(request_id, bytes_question, response):
    answers = [encode_resourse_record(rr) for rr in response["answers"]]
    flags = 0x8000 | 0x0080 | response["rcode"]   # QR=1, RA=1, rcode
    header = struct.pack("!HHHHHH", request_id, flags, 1, len(answers), 0, 0)
    return header + bytes_question + b"".join(answers)


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

        elif length == 0: # идентификатор конца
            if end is None:
                end = offset + 1
            return ".".join(tokens), end

        else: # обработка токена
            offset += 1
            tokens.append(data[offset:offset + length].decode("ascii"))
            offset += length


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
    elif rtype == 15: # MX
        priority = struct.unpack_from("!H", data, offset)[0]
        value = (priority, parse_name(data, offset + 2)[0])
    elif rtype == 16:  # TXT
        value, i = [], 0
        while i < rdlen:
            n = rdata[i]
            value.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
    else:
        value = rdata

    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "data": value
    }, offset + rdlen

def parse_message(data, qname):
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
    offset += len(qname) + 4

    for section, lenght in (("answers", an), ("authority", ns), ("additional", ar)):
        for _ in range(lenght):
            rr, offset = parse_resourse_record(data, offset)
            message[section].append(rr)
    return message
