import base64

def hamming_dist_byte(b1, b2):
    count = 0
    n1 = int(b1)
    n2 = int(b2)
    for i in [128, 64, 32, 16, 8, 4, 2, 1]:
        count += 0 if (n1 >= i) == (n2 >= i) else 1
        n1 = n1 % i
        n2 = n2 % i
    return count

def hamming_distance(stream1,stream2):
    count = 0
    mut_length = min(len(stream1), len(stream2))
    length_diff = abs(len(stream1) - len(stream2))
    for i in range(mut_length):
        count += hamming_dist_byte(stream1[i], stream2[i])
    
    return count + 8 * length_diff

test1_status = "PASSED" if hamming_distance(bytes("this is a test", "ascii"), bytes("wokka wokka!!!","ascii")) == 37 else "FAILED"
print("TEST HAMMING DISTANCE CHECK: "+test1_status)

def score_key_length(data, length):
    return hamming_distance(data[0:length], data[length:2*length]) / length

def guess_key_length(data):
    if len(data) < 2:
        return len(data)    
    guess = 1
    guess_score = len(data) * 8     #Maximum hamming distance (bitwise not of every bit.)
    for i in range(1,len(data)//2):
        sc = score_key_length(data,i)
        if sc < guess_score: #Prefer shorter key size (I think it would make for more reliable frequency analysis)
            print("Length: "+str(i) + " \tScore: "+ str(sc))
            guess = i
            guess_score = sc    
    return guess

def retrieve_data(filename):
    f = open(filename, "r")
    ls = f.readlines()
    f.close()
    sixtyfour = ""
    for l in ls:
        sixtyfour += l.strip()
    #print(sixtyfour)
    return base64.b64decode(sixtyfour)

ciphertext = retrieve_data("6.txt")
cipherhex = ciphertext.hex()
print("CIPHERTEXT LENGTH: " + str(len(ciphertext)))
key_guess_length = guess_key_length(ciphertext)
print("ESTIMATED KEY LENGTH: " + str(key_guess_length))

def get_blocks(text, num_blocks):
    if type(text) != bytes:
        return get_blocks(bytes(text, "ascii"), num_blocks)
    output = []
    for i in range(num_blocks):
        output.append(bytearray())
    for i in range(len(text)):
        output[i%num_blocks].append(text[i])
    for i in range(len(output)):
        output[i] = bytes(output[i]) #Convert from bytearray to bytes
    return output

def merge_blocks(blocks):
    #Compute length:
    total_len = 0
    for b in blocks:
        total_len += len(b)
    #Get output
    output = bytearray()
    for i in range(total_len):
        block = i % len(blocks)
        index = i // len(blocks)
        output.append((blocks[block])[index])
    return bytes(output)

#print(cipherhex)
stripe_test_status = "PASSED" if ciphertext == merge_blocks(get_blocks(ciphertext, 5)) else "FAILED"
print("TESTING STRIPING: " + stripe_test_status)

#helper-method to ensure alphabetical characters only
forbiddenchars = ""
restrictedchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,\'\"!/:?\n@#$%^&*()-_=+"
musthavechars = ""
scores = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}

#Simple summation method. should work for texts of the same length 
def sanitize(txt):
    output = ""
    for c in txt.lower():
        if c in scores.keys():
            output += c
    return output

def sum_score(txt):
    if not printable(txt):
        return 0
    points = 0
    for i in sanitize(txt.decode('ascii')):
        points += scores[i]
    return points

def printable(raw_text):
    for i in bytes(raw_text):
        #if i not in range(128) or chr(i) in forbiddenchars or chr(i) not in restrictedchars:
        if i not in range(32,128):
            return False
    '''for i in musthavechars:
        if i not in raw_text.decode('utf8'):
            return False'''
    return True

def decrypt(cipherbytes, keybyte):
    output = bytearray()
    for b in cipherbytes:
        output.append(b ^ keybyte)
    return bytes(output)

def guess_key_byte(raw_text):
    guess = 0
    guess_score = 0
    for i in range(256):
        plain_guess = decrypt(raw_text, i)
        sc = plain_guess.count(ord("e")) + plain_guess.count(ord("E"))
        if sc > guess_score:
            print(str(i) + "\t -> " + str(sc))
            guess = i
            guess_score = sc
    if guess_score == 0:
        print("NO KEY FOUND")
    return guess

def guess_key(data, length):
    output = []
    for cipherblock in get_blocks(data, length):
        output.append(guess_key_byte(cipherblock))
    return bytes(output)

full_key_guess = guess_key(ciphertext, key_guess_length)
print("KEY: " + str(full_key_guess))

def devig(data, key_bytes):
    keylen = len(key_bytes)
    plain_blocks = []
    for cipher_block in get_blocks(data, keylen):
        plain_blocks.append(decrypt(cipher_block, key_bytes[len(plain_blocks)]))
    return merge_blocks(plain_blocks)

def slowvig(data, key_bytes):
    keylen = len(key_bytes)
    output = bytearray()
    for i in range(len(data)):
        output.append(data[i] ^ key_bytes[i%keylen])
    return bytes(output)
test_decrypt_status = "PASSED" if devig(ciphertext, full_key_guess).decode("utf8") == slowvig(ciphertext, full_key_guess).decode("utf8") else "FAILED"
print("TESTING DECRYPTION: " + test_decrypt_status)
plain_raw = devig(ciphertext, full_key_guess)
plain_text = devig(ciphertext, full_key_guess).decode("utf8")
print("PLAINTEXT:\n" + str(devig(ciphertext, full_key_guess).decode("utf8")))
print("PLAINTEXT LENGTH: " + str(len(plain_raw)))