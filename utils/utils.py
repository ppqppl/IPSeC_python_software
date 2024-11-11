from operator import length_hint


def print_str(str):
    print(str)

def hex_dump(data):
    for i in range(0, len(data)):
        if i % 16 == 0 and i != 0:
            print('')
        print('%02x ' % data[i], end='')
    print('')

def str_dump(data):
    for i in range(0, len(data)):
        if i % 32 == 0 and i != 0:
            print('')
        if i % 2 == 0 and i % 32 != 0:
            print(' ',end='')
        print(data[i],end='')
    print('')

def hexchar_2_int(char):    # 'a' -> 10
    char_int = 0
    if 'a' <= char <= 'f' :
        char_int = 10 + ord(char) - ord('a')
    elif 'A' <= char <= 'F':
        char_int = 10 + ord(char) - ord('A')
    elif '0' <= char <= '9':
        char_int = ord(char) - ord('0')
    # print(char_int)
    return char_int

def int_2_hexchar(data):    # 10 -> 'a'
    if 0 <= data <= 9:
        return str(data)
    else:
        return chr(int(ord('a') + data - 10))

def int_2_hexstr_ip(data): # 192 -> "c0"
    hex_str = ""
    for i in range(len(str(data))):
        int_num = data%16
        hex_str += int_2_hexchar(int_num)
        data = int(data/16)
    hex_str += "0"
    hex_str = "".join(reversed(hex_str[0:2:1]))
    # print(hex_str)
    return hex_str

def str_2_hexbytes(data):   # "abc" -> b'\xab\xc0'
    str_out = b''
    j = '0'
    for i in range(0,len(data)):
        if i % 2 == 1:
            j = j + data[i]
            # print(j)
            str_out = str_out + bytes.fromhex(j)
            # print(bytes.fromhex(j))
            j = 0
        else:
            if i == len(data) - 1:
                j = data[i] + '0'
                str_out = str_out + bytes.fromhex(j)
            else:
                j = data[i]
    # hex_dump(str_out)
    return str_out

def hexbytes_2_str(data):   # b'\x00\x01' -> "0001"
    length = len(data)
    str_out = ""
    for i in range(length):
        data_int = int(data[i])
        str_out += int_2_hexchar(int(data_int / 16))
        str_out += int_2_hexchar(int(data_int % 16))
    # str_dump(str_out)
    return str_out

def macstr_2_str(data): # "aa:bb:cc:dd:ee:ff" -> "aabbccddeeff"
    length = len(data)
    mac_str = ""
    for i in range(length):
        mac_str += data[i] if (i + 1) % 3 != 0 else ''
    return mac_str

def ipstr_2_hexipstr(data): # "192.168.1.1" -> "c0.a8.01.01"
    length = len(data)
    ip_int = 0
    data_str = ""
    for i in range(length):
        # print(data[i])
        # print(ip_int)
        if data[i] == '.':
            data_str += int_2_hexstr_ip(ip_int) + '.'
            ip_int = 0
        else:
            ip_int *= 10
            ip_int += int(data[i])
    data_str += int_2_hexstr_ip(ip_int)
    return data_str

def hexipstr_2_str(data):   # "c0.a8.01.01" -> "c0a80101"
    length = len(data)
    ip_str = ""
    for i in range(length):
        ip_str += data[i] if (i + 1) % 3 != 0 else ''
    return ip_str

def ipstr_2_hexstr(data):   # "192.168.1.1" -> "c0aa80101"
    ip_str = ipstr_2_hexipstr(data)
    ip_str = hexipstr_2_str(ip_str)
    return ip_str

# print(str_2_hexbytes("bcdd"))
# hex_2_str(b'\x02\xff')
# print(hexbytes_2_str(b'\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07'))
# hex_dump(b'\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07')
# print(str_2_hexbytes("abc"))
# a = 120
# b = str(a)
# print(b)
# print(type(b))
# print(int_2_hexstr(168))
# print(hexipstr_2_str(ipstr_2_hexipstr("192.168.10.10")))
# print(ipstr_2_hexstr("192.168.01.01"))
# print(macstr_2_str("aa-bb-cc-dd-ee-ff"))
# print(str_2_hexbytes("1000"))
# data = 10011
# data_hex = hex(data)
# data_str = str(data_hex)[2:]
# data_str_reserve = data_str[::-1]
# data_out_reserve = data_str_reserve.ljust(8,'0')
# print(data_hex)
# print(data_str)
# print(data_str_reserve)
# print(data_out_reserve)
# print(str_2_hexbytes(data_out_reserve[::-1]))
# hex_dump(str_2_hexbytes(data_out_reserve[::-1]))
# data = 0800
# data_str = str(data)
# print(data_str)
