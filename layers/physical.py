def physical_layer(data):
    binary_data = ' '.join(format(ord(char), '08b') for char in data)
    return "BINARY_DATA: " + binary_data