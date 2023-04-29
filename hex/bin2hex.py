#需要处理
def bin_to_hex_string(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    hex_string = ""
    for byte in content:
        hex_string += "\\x" + format(byte, "02x")
    return hex_string

hex_string = bin_to_hex_string("calculator.bin")
print(hex_string)