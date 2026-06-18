from utils.leb128 import read_uleb128_fast, read_sleb128, write_uleb128, write_sleb128

def parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods):
    start = pos
    header = data[pos]
    pos += 1
    value_type = header & 0x1f
    value_arg = header >> 5
    
    # Types that contain indices:
    # 0x17 = STRING
    # 0x18 = TYPE
    # 0x19 = FIELD
    # 0x1A = METHOD
    # 0x1B = ENUM (field index)
    
    if value_type in (0x17, 0x18, 0x19, 0x1A, 0x1B):
        size = value_arg + 1
        idx = 0
        for i in range(size):
            idx |= data[pos + i] << (i * 8)
        pos += size
        
        if value_type == 0x17: hlw_strs.add(idx)
        elif value_type == 0x18: hlw_types.add(idx)
        elif value_type in (0x19, 0x1B): hlw_fields.add(idx)
        elif value_type == 0x1A: hlw_methods.add(idx)
        
        return pos - start, (value_type, idx)
    
    elif value_type == 0x1C: # ARRAY
        size, c = read_uleb128_fast(data, pos)
        pos += c
        elements = []
        for _ in range(size):
            c, elem = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods)
            pos += c
            elements.append(elem)
        return pos - start, (value_type, elements)
    
    elif value_type == 0x1D: # ANNOTATION
        type_idx, c = read_uleb128_fast(data, pos)
        pos += c
        hlw_types.add(type_idx)
        size, c = read_uleb128_fast(data, pos)
        pos += c
        elements = []
        for _ in range(size):
            name_idx, c = read_uleb128_fast(data, pos)
            pos += c
            hlw_strs.add(name_idx)
            c, elem = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods)
            pos += c
            elements.append((name_idx, elem))
        return pos - start, (value_type, type_idx, elements)
    
    elif value_type in (0x1E, 0x1F): # NULL, BOOLEAN
        return pos - start, (value_type, value_arg)
        
    else:
        # Primitive types (BYTE, SHORT, CHAR, INT, LONG, FLOAT, DOUBLE)
        size = value_arg + 1
        val = data[pos : pos + size]
        pos += size
        return pos - start, (value_type, val)

def parse_encoded_array(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods):
    start = pos
    size, c = read_uleb128_fast(data, pos)
    pos += c
    elements = []
    for _ in range(size):
        c, elem = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods)
        pos += c
        elements.append(elem)
    return elements

def rebuild_encoded_value(elem, im):
    out = bytearray()
    value_type = elem[0]
    
    if value_type in (0x17, 0x18, 0x19, 0x1A, 0x1B):
        idx = elem[1]
        new_idx = 0
        if value_type == 0x17: new_idx = im.str_restruct_idx.get(im.origin_strings[idx] if idx < len(im.origin_strings) else "", 0)
        elif value_type == 0x18: new_idx = im.type_restruct_idx.get(idx, 0)
        elif value_type in (0x19, 0x1B): new_idx = im.field_restruct_idx.get(idx, 0)
        elif value_type == 0x1A: new_idx = im.method_restruct_idx.get(idx, 0)
        
        # Calculate size needed
        temp = new_idx
        size = 1
        while temp > 0xff:
            temp >>= 8
            size += 1
            
        out.append(( (size - 1) << 5 ) | value_type)
        temp = new_idx
        for _ in range(size):
            out.append(temp & 0xff)
            temp >>= 8
            
    elif value_type == 0x1C:
        elements = elem[1]
        out.append(value_type) # ARRAY has value_arg = 0
        out.extend(write_uleb128(len(elements)))
        for e in elements:
            out.extend(rebuild_encoded_value(e, im))
            
    elif value_type == 0x1D:
        type_idx = elem[1]
        elements = elem[2]
        out.append(value_type) # ANNOTATION
        out.extend(write_uleb128(im.type_restruct_idx.get(type_idx, 0)))
        out.extend(write_uleb128(len(elements)))
        for name_idx, e in elements:
            out.extend(write_uleb128(im.str_restruct_idx.get(im.origin_strings[name_idx] if name_idx < len(im.origin_strings) else "", 0)))
            out.extend(rebuild_encoded_value(e, im))
            
    elif value_type in (0x1E, 0x1F):
        out.append((elem[1] << 5) | value_type)
        
    else:
        val = elem[1]
        out.append(( (len(val) - 1) << 5 ) | value_type)
        out.extend(val)
        
    return out

def rebuild_encoded_array(elements, im):
    out = bytearray()
    out.extend(write_uleb128(len(elements)))
    for e in elements:
        out.extend(rebuild_encoded_value(e, im))
    return out

def parse_debug_info(data, pos, hlw_strs, hlw_types):
    start = pos
    line_start, c = read_uleb128_fast(data, pos)
    pos += c
    parameters_size, c = read_uleb128_fast(data, pos)
    pos += c
    
    parameter_names = []
    for _ in range(parameters_size):
        name_idx, c = read_uleb128_fast(data, pos) # actually uleb128p1
        pos += c
        parameter_names.append(name_idx)
        if name_idx != 0:
            hlw_strs.add(name_idx - 1)
            
    opcodes = []
    while True:
        opcode = data[pos]
        pos += 1
        if opcode == 0x00: # DBG_END_SEQUENCE
            opcodes.append((opcode,))
            break
        elif opcode == 0x01: # DBG_ADVANCE_PC
            addr_diff, c = read_uleb128_fast(data, pos)
            pos += c
            opcodes.append((opcode, addr_diff))
        elif opcode == 0x02: # DBG_ADVANCE_LINE
            line_diff, c = read_sleb128(data, pos)
            pos += c
            opcodes.append((opcode, line_diff))
        elif opcode == 0x03: # DBG_START_LOCAL
            v_reg, c = read_uleb128_fast(data, pos)
            pos += c
            name_idx, c = read_uleb128_fast(data, pos) # uleb128p1
            pos += c
            type_idx, c = read_uleb128_fast(data, pos) # uleb128p1
            pos += c
            if name_idx != 0: hlw_strs.add(name_idx - 1)
            if type_idx != 0: hlw_types.add(type_idx - 1)
            opcodes.append((opcode, v_reg, name_idx, type_idx))
        elif opcode == 0x04: # DBG_START_LOCAL_EXTENDED
            v_reg, c = read_uleb128_fast(data, pos)
            pos += c
            name_idx, c = read_uleb128_fast(data, pos) # uleb128p1
            pos += c
            type_idx, c = read_uleb128_fast(data, pos) # uleb128p1
            pos += c
            sig_idx, c = read_uleb128_fast(data, pos) # uleb128p1
            pos += c
            if name_idx != 0: hlw_strs.add(name_idx - 1)
            if type_idx != 0: hlw_types.add(type_idx - 1)
            if sig_idx != 0: hlw_strs.add(sig_idx - 1)
            opcodes.append((opcode, v_reg, name_idx, type_idx, sig_idx))
        elif opcode in (0x05, 0x06): # DBG_END_LOCAL, DBG_RESTART_LOCAL
            v_reg, c = read_uleb128_fast(data, pos)
            pos += c
            opcodes.append((opcode, v_reg))
        elif opcode == 0x09: # DBG_SET_FILE
            name_idx, c = read_uleb128_fast(data, pos) # uleb128p1
            pos += c
            if name_idx != 0: hlw_strs.add(name_idx - 1)
            opcodes.append((opcode, name_idx))
        else: # 0x07, 0x08, and >= 0x0a
            opcodes.append((opcode,))
            
    return {
        'line_start': line_start,
        'parameter_names': parameter_names,
        'opcodes': opcodes
    }

def rebuild_debug_info(info, im):
    out = bytearray()
    out.extend(write_uleb128(info['line_start']))
    out.extend(write_uleb128(len(info['parameter_names'])))
    for name_idx in info['parameter_names']:
        if name_idx == 0:
            out.extend(write_uleb128(0))
        else:
            orig_idx = name_idx - 1
            new_idx = im.str_restruct_idx.get(im.origin_strings[orig_idx] if orig_idx < len(im.origin_strings) else "", 0)
            out.extend(write_uleb128(new_idx + 1))
            
    for op in info['opcodes']:
        opcode = op[0]
        out.append(opcode)
        if opcode == 0x01:
            out.extend(write_uleb128(op[1]))
        elif opcode == 0x02:
            out.extend(write_sleb128(op[1]))
        elif opcode == 0x03:
            out.extend(write_uleb128(op[1]))
            out.extend(write_uleb128(im.str_restruct_idx.get(im.origin_strings[op[2]-1], 0) + 1 if op[2] != 0 else 0))
            out.extend(write_uleb128(im.type_restruct_idx.get(op[3]-1, 0) + 1 if op[3] != 0 else 0))
        elif opcode == 0x04:
            out.extend(write_uleb128(op[1]))
            out.extend(write_uleb128(im.str_restruct_idx.get(im.origin_strings[op[2]-1], 0) + 1 if op[2] != 0 else 0))
            out.extend(write_uleb128(im.type_restruct_idx.get(op[3]-1, 0) + 1 if op[3] != 0 else 0))
            out.extend(write_uleb128(im.str_restruct_idx.get(im.origin_strings[op[4]-1], 0) + 1 if op[4] != 0 else 0))
        elif opcode in (0x05, 0x06):
            out.extend(write_uleb128(op[1]))
        elif opcode == 0x09:
            out.extend(write_uleb128(im.str_restruct_idx.get(im.origin_strings[op[1]-1], 0) + 1 if op[1] != 0 else 0))
            
    return out
