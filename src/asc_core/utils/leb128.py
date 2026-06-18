# Auth: MG1937

# DONT PARSE IT, JUST FUCKING MATCH IT!!!!!
# VERY FKING FAST!
def read_uleb128_fast(data : bytes, pos):
    b = data[pos]
    if b < 128:
        return b, 1
    
    res = b & 0x7f
    b = data[pos + 1]
    res |= (b & 0x7f) << 7
    if b < 128: return res, 2
    
    b = data[pos + 2]
    res |= (b & 0x7f) << 14
    if b < 128: return res, 3
    
    b = data[pos + 3]
    res |= (b & 0x7f) << 21
    if b < 128: return res, 4
    
    b = data[pos + 4]
    res |= (b & 0x7f) << 28
    return res, 5

def write_uleb128(value):
    out = bytearray()
    if value == 0:
        return b'\x00'
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return out

def read_sleb128(data, pos):
    result = 0
    shift = 0
    start = pos
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        shift += 7
        if not (byte & 0x80):
            break
    if shift < 32 and (byte & 0x40):
        result |= - (1 << shift)
    return result, pos - start

def write_sleb128(value):
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7f
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        out.append(byte)
    return out

def read_uleb128_len(data, pos):
    if data[pos] < 128:
        return 1
    if data[pos+1] < 128:
        return 2
    elif data[pos+2] < 128:
        return 3
    elif data[pos+3] < 128:
        return 4
    elif data[pos+4] < 128:
        return 5
    else:
        p = pos + 5
        while data[p] >= 128:
            p += 1
        return p - pos + 1
