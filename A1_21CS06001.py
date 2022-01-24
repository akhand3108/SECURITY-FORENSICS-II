import cv2
import numpy as np

def get_key():
    myfile = open('C:\\Users\\user\\Desktop\\secret_key.txt', 'rt') 
    key1 = myfile.read()        
    myfile.close()                   
    return key1


def to_bin(data):
    """Convert `data` to binary format as string"""
    if isinstance(data, str):
        return ''.join([ format(ord(i), "08b") for i in data ])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [ format(i, "08b") for i in data ]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")
		
		
def encode(key, image_name, secret_data):
    
    image = cv2.imread(image_name)
    
    n_bytes = image.shape[0] * image.shape[1] * 3 // 8
    print("[*] Maximum bytes to encode:", n_bytes)
    if len(secret_data) > n_bytes:
        raise ValueError("[!] Insufficient bytes, need bigger image or less data.")
    print("[*] Encoding data...")
    
    
   
    data_index = 0
    
    binary_secret_data = to_bin(secret_data)
    binary_key = to_bin(key)
    
    enc_data = ([])
    for i in range(0, len(binary_secret_data)): 
         enc_data.append(int(binary_secret_data[i]) ^ int(binary_key[i%8]))

    

    data_len = len(enc_data)
    for row in image:
        for pixel in row:
            r, g, b = to_bin(pixel)
            
            if ((data_index < data_len) and (( int(r[-2]) ^ int(binary_key[(data_index)%8])) == 1)):
                pixel[0] = int(r[:-1] + str(enc_data[data_index]), 2)
                data_index += 1
            if ((data_index < data_len) and (( int(g[-2]) ^ int(binary_key[(data_index)%8])) == 1)):
                
                pixel[1] = int(g[:-1] + str(enc_data[data_index]), 2)
                data_index += 1
            if ((data_index < data_len) and (( int(b[-2]) ^ int(binary_key[(data_index)%8])) == 1)):
                
                pixel[2] = int(b[:-1] + str(enc_data[data_index]), 2)
                data_index += 1
            
            if data_index >= data_len:
                break
    return image


def decode(key, image_name, n):
    print("[+] Decoding...")
    
    image = cv2.imread(image_name)
    binary_data = ""
    data_index = 0
    binary_key = to_bin(key)
    for row in image:
        for pixel in row:
            r, g, b = to_bin(pixel)
            if ((( int(r[-2]) ^ int(binary_key[(data_index)%8])) == 1)):
                
                binary_data += r[-1]
                data_index += 1
            if ((( int(g[-2]) ^ int(binary_key[(data_index)%8]) ) == 1)):
                
                binary_data += g[-1]
                data_index += 1
            if ((( int(b[-2]) ^ int(binary_key[(data_index)%8]) ) == 1)):
                
                binary_data += b[-1]
                data_index += 1

            if data_index > n:
                break

    all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
    
    

    dec_data = []
    
    for i in range(0, len(all_bytes)-1):
        dec_str = ""
        for j in range(0,8): 
            dec_str += str(int(binary_data[i*8 + j]) ^ int(binary_key[j]))
        dec_data.append(dec_str)

    

    decoded_data = ""
    for byte in dec_data:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-5:] == '=====' :
            break
    
    return decoded_data[:-5]

def steganography():
    input_image = "C:\\Users\\user\\Desktop\\IMG2.png"
    output_image = "C:\\Users\\user\\Desktop\\IMGSTEG2.png"
    delimiter = "====="
    secret_data = "This is a top secret message." + delimiter
    binary_secret_data = to_bin(secret_data)
    n = len(binary_secret_data)
    key = get_key()
    
    encoded_image = encode(key, image_name=input_image, secret_data=secret_data)
    print("Data encoded and Image generated")
    
    cv2.imwrite(output_image, encoded_image)
    
    decoded_data = decode(key, output_image, n)
    print("[+] Decoded data:", decoded_data)

def calculate_PSNR():
    input_image = cv2.imread("C:\\Users\\user\\Desktop\\IMG2.png")
    output_image = cv2.imread("C:\\Users\\user\\Desktop\\IMGSTEG2.png")

    psnr = cv2.PSNR(input_image, output_image)
    print(psnr)
    
    
steganography()
calculate_PSNR()