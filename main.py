# piesweeper by Yoti
# based on pysweeper by Khubik
# which based on keygen by Proxima

# Imports
import sys
print('piesweeper is running on', sys.platform)
if sys.platform == 'RP2040':
    import aesio  # from aesio import AES
    import board
    import busio
    uart = busio.UART(board.TX, board.RX, baudrate=19200, bits=8, parity=busio.UART.Parity.EVEN, stop=1)
    uart.reset_input_buffer()
    try:
        import neopixel
        led = neopixel.NeoPixel(board.NEOPIXEL, 1)
        led.brightness = 0.1
        led[0] = (0, 0, 0)
    except:
        print('Warning: NeoPixel lib not found')
else:
    from Crypto.Cipher import AES
    import serial
    import serial.tools.list_ports

    port = None
    if len(sys.argv) > 1:
        print('User defined port:', sys.argv[1])
        port = sys.argv[1]
    else:
        for item in serial.tools.list_ports.comports():
            print(item)
            port = item.device
            break
    if port is not None:
        try:
            uart = serial.Serial(port, baudrate=19200, bytesize=8, parity=serial.PARITY_EVEN, stopbits=serial.STOPBITS_TWO)
            if (uart.is_open):
                uart.reset_input_buffer()
                uart.reset_output_buffer()
            else:
                print('Error: COM port can\'t be opened!')
                sys.exit()
        except:
            print('Error: COM port is busy or can\'t be opened!')
            sys.exit()
    else:
        print('Error: COM port not found!')
        sys.exit()
import time
from binascii import hexlify, unhexlify

# Keys
fixed_answers = {\
    0x01: 'a5050610c30676',\
    0x02: 'a503061b36',\
    0x03: 'a5040636100a',\
    0x04: 'a504066810d8',\
    0x07: 'a50406080741',\
    0x08: 'a50406e2046a',\
    0x09: 'a5040601044b',\
    0x0b: 'a504060f0041',\
    0x0c: 'a50606ffffffff52',\
    0x0d: 'a507069d1010281454',\
    0x16: 'a51306536f6e79456e65726779446576696365736b'\
}

keystore = {\
    0x00: '5c52d91cf382aca489d88178ec16297b',\
    0x01: '9d4f50fce1b68e1209307ddba6a5b5aa',\
    0x02: '0975988864acf7621bc0909df0fcabff',\
    0x03: 'c9115ce2064a2686d8d6d9d08cde3059',\
    0x04: '667539d2fb4273b2903fd7a39ed2c60c',\
    0x05: 'f4faef20f4dbab31d18674fd8f990566',\
    0x06: 'ea0c811363d7e930f961135a4f352ddc',\
    0x08: '0a2e73305c382d4f310d0aed84a41800',\
    0x09: 'd20474308fe269046ed7bb07cf1cff43',\
    0x0a: 'ac00c0e3e80af0683fdd1745194543bd',\
    0x0b: '0177d750bdfd2bc1a0493a134a4c6acf',\
    0x0c: '05349170939345ee951a14843334a0de',\
    0x0d: 'dff3fcd608b05597cf09a23bd17d3fd2',\
    0x2f: '4aa7c7b01134466fac82163e4bb51bf9',\
    0x97: 'cac8b87acd9ec49690abe0813920b110',\
    0xb3: '03beb65499140483ba187a64ef90261d',\
    0xd9: 'c7ac1306defe39ec83a1483b0ee2ec89',\
    0xeb: '418499be9d35a3b9fc6ad0d6f041bb26'\
}

challenge1_secret = {\
    0x00: 'd2072253a4f27468',\
    0x01: 'f5d7d4b575f08e4e',\
    0x02: 'b37a16ef557bd089',\
    0x03: 'cc699581fd89126c',\
    0x04: 'a04e32bba7139e46',\
    0x05: '495e034794931d7b',\
    0x06: 'b0b809833989fae2',\
    0x08: 'ad4043b256eb458b',\
    0x0a: 'c2377e8a74096c5f',\
    0x0d: '581c7f1944f96262',\
    0x2f: 'f1bc562bd55bb077',\
    0x97: 'af6010a846f741f3',\
    0xb3: 'dbd3aea4db046410',\
    0xd9: '90e1f0c00178e3ff',\
    0xeb: '0bd9027e851fa123'\
}

challenge2_secret = {\
    0x00: 'f4e04313ad2eb4db',\
    0x01: 'fe7d7899bfec47c5',\
    0x02: '865e3eef9dfbb1fd',\
    0x03: '306f3a03d86cbee4',\
    0x04: 'ff72bd2b83b89d2f',\
    0x05: '8422dfeae21b63c2',\
    0x06: '58b95aaef399dbd0',\
    0x08: '67c07215d96b39a1',\
    0x0a: '093ec519af0f502d',\
    0x0d: '318053875c203e24',\
    0x2f: '1bdf2433eb29155b',\
    0x97: '9deec01144b66f41',\
    0xb3: 'e32b8f56b2641298',\
    0xd9: 'c34a6a7b205fe8f9',\
    0xeb: 'f791ed0b3f49a448'\
}

go_key1 = 'c66e9ed6ecbcb121b7465d25037d6646'
go_key2 = 'da24dab43a61cbdf61fd255d0aea7957'
go_secret = '880e2a94110926b20e53e22ae648ae9d'
go_const = '82828282'

newmap = [
    0x00, 0x04, 0x08, 0x0C, 0x01, 0x05, 0x09, 0x0D, 0x02, 0x06, 0x0A, 0x0E, 0x03, 0x07, 0x0B, 0x0F, 
]

# Functions
def checksum(cs_in):
    hs = hex(sum(unhexlify(cs_in)))
    b = unhexlify(hs[len(hs)-2:len(hs)])
    return(255 - int.from_bytes(b, 'little', signed=False)).to_bytes(1, 'little', signed=False)

def MatrixSwap(key):
    temp = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    for i in range(0, len(key)):
        temp[i] = key[newmap[i]]
    return(temp[0:len(key)])

def MixChallenge1(version, challenge):
    temp = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    secret1 = unhexlify(challenge1_secret[version])
    temp[0x00] = secret1[0x00]
    temp[0x04] = secret1[0x01]
    temp[0x08] = secret1[0x02]
    temp[0x0C] = secret1[0x03]
    temp[0x01] = secret1[0x04]
    temp[0x05] = secret1[0x05]
    temp[0x09] = secret1[0x06]
    temp[0x0D] = secret1[0x07]
    temp[0x02] = challenge[0x00]
    temp[0x06] = challenge[0x01]
    temp[0x0A] = challenge[0x02]
    temp[0x0E] = challenge[0x03]
    temp[0x03] = challenge[0x04]
    temp[0x07] = challenge[0x05]
    temp[0x0B] = challenge[0x06]
    temp[0x0F] = challenge[0x07]
    return(temp)

def MixChallenge2(version, challenge):
    temp = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    secret2 = unhexlify(challenge2_secret[version])
    temp[0x00] = challenge[0x00]
    temp[0x04] = challenge[0x01]
    temp[0x08] = challenge[0x02]
    temp[0x0C] = challenge[0x03]
    temp[0x01] = challenge[0x04]
    temp[0x05] = challenge[0x05]
    temp[0x09] = challenge[0x06]
    temp[0x0D] = challenge[0x07]
    temp[0x02] = secret2[0x00]
    temp[0x06] = secret2[0x01]
    temp[0x0A] = secret2[0x02]
    temp[0x0E] = secret2[0x03]
    temp[0x03] = secret2[0x04]
    temp[0x07] = secret2[0x05]
    temp[0x0B] = secret2[0x06]
    temp[0x0F] = secret2[0x07]
    return(temp)

def AesCbcDecrypt(key, inp):
    outp = bytearray(len(inp))
    cipher = aesio.AES(key, aesio.MODE_CBC)
    cipher.decrypt_into(inp, outp)
    return(hexlify(outp))

def AesEcbEncrypt(key, inp):
    outp = bytearray(len(inp))
    cipher = aesio.AES(key, aesio.MODE_ECB)
    cipher.encrypt_into(inp, outp)
    return(hexlify(outp))

def b2s(b):
    s = str()
    for i in b:
        t = hex(i)[2:]
        if len(t) == 1:
            s += '0'
        s += t
    return(s)

def i2b(i):
    return(i.to_bytes(1, 'little', signed=False))

def dprint(obj, txt=''):
    if type(obj) == int:
        print('debug:', txt, obj, hex(obj), type(obj))
    else:
        print('debug:', txt, obj, type(obj), len(obj))

# Main
sn = 'FFFFFFFF'
print('Using', sn, 'as serial number')
is80 = False
is81 = False
while True:
    while uart.in_waiting < 4:
        try:
            if is80 == True and is81 == False:
                led[0] = (255, 0, 0)  # red for error
            else:
                led[0] = (0, 0, 255)  # blue for waiting
        except:
            pass
        time.sleep(0.001)

    try:
        led[0] = (0, 255, 0)  # green for working
    except:
        pass

    pk_head = uart.read(1)
    if pk_head[0] == 0x5A :  # <- PSP
        pk_len = uart.read(1); time.sleep(0.001)
        pk_cmd = uart.read(1); time.sleep(0.001)
        pk_body = b''
        for i in range(pk_len[0] - 2):
            pk_body += uart.read(1); time.sleep(0.001)
        pk_end = uart.read(1); time.sleep(0.001)
        uart.reset_input_buffer(); time.sleep(0.001)
        check = pk_head + pk_len + pk_cmd + pk_body
        check = checksum(str(hexlify(check), 'ascii'))
        #dprint(check, 'check')  # bytes(1)
        #dprint(check[0], 'check[0]')  # int == 0x92
        #dprint(hex(check[0]), 'hex(check[0])')  # str(4) == 0x92
        #dprint(str(check), 'str(check)')  # str(7) == b'\x97'
        #dprint(hexlify(check), 'hexlify(check)') bytes(2) == b'97'
        if check != pk_end:
            print('Warning: bad CRC value', hex(pk_end[0]))

        if len(pk_body) > 0:
            print('->',\
                  str(hexlify(pk_head), 'ascii'),\
                  str(hexlify(pk_len), 'ascii'),\
                  str(hexlify(pk_cmd), 'ascii'),\
                  str(hexlify(pk_body), 'ascii'),\
                  str(hexlify(pk_end), 'ascii'))
        else:
            print('->',\
                  str(hexlify(pk_head), 'ascii'),\
                  str(hexlify(pk_len), 'ascii'),\
                  str(hexlify(pk_cmd), 'ascii'),\
                  str(hexlify(pk_end), 'ascii'))

        if pk_cmd[0] in fixed_answers:
            answer_s = fixed_answers[pk_cmd[0]]  # str(X)
            answer_b = unhexlify(answer_s)  # bytes(X/2)

            print('<-',
                  answer_s[:2],\
                  answer_s[2:4],\
                  answer_s[4:6],\
                  answer_s[6:len(answer_s)-2],\
                  answer_s[len(answer_s)-2:],)

            for i in answer_b:
                uart.write(i2b(i))
                time.sleep(0.001)
                uart.reset_input_buffer()
                time.sleep(0.001)
        elif pk_cmd[0] in [0x80, 0x81, 0x90]:
            if pk_cmd[0] == 0x80:
                is80 = True
                version = pk_body[0]
                req = pk_body[1:]

                mchallenge1 = MixChallenge1(version, req)
                #dprint(mchallenge1, 'MixChallenge1')
                key = unhexlify(keystore[version])
                inp = bytes(MatrixSwap(mchallenge1))
                challenge1a = AesEcbEncrypt(key, inp)

                second = bytearray(0x10)
                second = unhexlify(challenge1a.decode('ascii'))
                key = unhexlify(keystore[version])
                inp = bytes(second)
                tmp = unhexlify(AesEcbEncrypt(key, inp))
                challenge1b = MatrixSwap(tmp)
                response1 = bytes(second[0:8]) + bytes(challenge1b[0:8])

                answer_s = 'a51206' + b2s(response1)
                chksum_b = checksum(answer_s)
                answer_s += b2s(chksum_b)
                answer_b = unhexlify(answer_s)

                print('<-',
                      answer_s[:2],\
                      answer_s[2:4],\
                      answer_s[4:6],\
                      answer_s[6:len(answer_s)-2],\
                      answer_s[len(answer_s)-2:],)

                for i in answer_b:
                    #dprint(i)
                    uart.write(i2b(i))
                    time.sleep(0.001)
                    uart.reset_input_buffer()
                    time.sleep(0.001)
            elif pk_cmd[0] == 0x81:
                is81 = True
                req = pk_body[:]

                mchallenge2 = MixChallenge2(version, challenge1b[0:8])
                #dprint(version, 'version')
                #dprint(challenge1b[0:8], 'challenge1b[0:8]')
                #dprint(mchallenge2, 'MixChallenge2')

                key = unhexlify(keystore[version])
                #dprint(key, 'key2a')
                inp = bytes(MatrixSwap(mchallenge2))
                #dprint(inp, 'inp2a')
                challenge2 = unhexlify(AesEcbEncrypt(key, inp))
                #dprint(challenge2, 'challenge2')

                key = unhexlify(keystore[version])
                #dprint(key, 'key2b')
                inp = challenge2
                #dprint(inp, 'inp2b')
                response2 = unhexlify(AesEcbEncrypt(key, inp))
                #dprint(response2, 'response2')

                answer_s = 'a50a06' + b2s(response2[0:8])
                #dprint(answer_s, 'answer_s')
                chksum_b = checksum(answer_s)
                answer_s += b2s(chksum_b)  # str(X)
                #dprint(answer_s, 'answer_s')
                answer_b = unhexlify(answer_s)  # bytes(X/2)

                print('<-',
                      answer_s[:2],\
                      answer_s[2:4],\
                      answer_s[4:6],\
                      answer_s[6:len(answer_s)-2],\
                      answer_s[len(answer_s)-2:],)

                for i in answer_b:
                    #dprint(i)
                    uart.write(i2b(i))
                    time.sleep(0.001)
                    uart.reset_input_buffer()
                    time.sleep(0.001)
            elif pk_cmd[0] == 0x90:
                print(0x90)

                answer_s = 'a52a06'# + b2s(response1)
                chksum_b = checksum(answer_s)
                answer_s += b2s(chksum_b)
                answer_b = unhexlify(answer_s)

                try:
                    led[0] = (255, 0, 0)  # red for error
                except:
                    pass
                sys.exit()
        else:
            print('Warning: unknown command', hex(pk_cmd[0]))
    elif pk_head[0] == 0xA5:  # -> PSP
        pass

    time.sleep(0.001)
