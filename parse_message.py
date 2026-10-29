import base64
import struct
import socket

# 2.22.multiply.test.com
def multiply_ip(name):
    tokens = name.lower().rstrip(".").split(".")
    if "multiply" not in tokens:
        return None
    nums = []
    for token in reversed(tokens[:tokens.index("multiply")]):
        if not token.isdigit():
            break
        nums.append(int(token))
    if not nums:
        return None
    x = 1
    for n in nums:
        x = x * n % 256
    return f"127.0.0.{x}"


def encode_name(name):
    out = b""
    for token in name.rstrip(".").split("."):
        out += bytes([len(token)]) + token.encode("ascii")
    return out + b"\x00"

qname = encode_name("insma.urfu.ru")   # один раз
# в каждый запрос: header + qname + struct.pack("!HH", qtype, 1)

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
    elif rtype == 15:  # MX
        pref = struct.unpack_from("!H", data, offset)[0]
        value = (pref, parse_name(data, offset + 2)[0])
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
