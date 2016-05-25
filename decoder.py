# coding=utf-8
import sys
import binascii


# -------------------------------------------------------------#
def B2I(b):
    assert type(b) is bytes
    return int.from_bytes(b, byteorder='big')


# -------------------------------------------------------------#
def I2B(i, length):
    assert type(i) is int
    assert type(length) is int and length >= 0
    return int.to_bytes(i, length, byteorder='big')


# -------------------------------------------------------------#
def HMAC_SHA256(key, msg):
    import hmac
    return hmac.new(key, msg, 'sha256').digest()


# -------------------------------------------------------------#
def SYSTEM(command, stdin=None):
    from subprocess import Popen, PIPE
    proc = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = proc.communicate(stdin)
    return stdout, stderr, proc.returncode


# -------------------------------------------------------------#
def RSA_DECRYPT(skfilename, ciphertext):
    assert type(skfilename) is str
    assert type(ciphertext) is bytes
    stdout, stderr, retcode = SYSTEM((
        'openssl', 'rsautl', '-decrypt', '-inkey', skfilename
    ), ciphertext)
    assert retcode == 0 and stderr == b''
    return stdout


# -------------------------------------------------------------#
def TLS_PRF(secret, label, seed, n_bytes):
    assert type(secret) is bytes
    assert type(label) is bytes
    assert type(seed) is bytes
    assert type(n_bytes) is int and n_bytes >= 0
    last_A = label + seed
    result = b''
    while len(result) < n_bytes:
        last_A = HMAC_SHA256(secret, last_A)
        result += HMAC_SHA256(secret, last_A + label + seed)
    return result[:n_bytes]


# -------------------------------------------------------------#
def AES128CBC_DECRYPT(secret_key, ini_vector, ciphertext):
    assert type(secret_key) is bytes and len(secret_key) == 16
    assert type(ini_vector) is bytes and len(ini_vector) == 16
    assert type(ciphertext) is bytes and len(ciphertext) % 16 == 0
    stdout, stderr, retcode = SYSTEM((
        'openssl', 'enc', '-aes-128-cbc', '-d', '-nopad',
        '-K', ''.join('%02x' % x for x in secret_key),
        '-iv', ''.join('%02x' % x for x in ini_vector)
    ), ciphertext)
    assert retcode == 0 and stderr == b''
    return stdout


# -------------------------------------------------------------#

def main():
    in1, in2, in3, out1, out2 = sys.argv[1:]
    f1 = open(in1, 'rb')
    f2 = open(in2, 'rb')
    o1 = open(out1, 'w')
    o2 = open(out2, 'w')

    content1 = content3 = f1.read()  # 客戶端發出的封包
    content2 = content4 = f2.read()  # 伺服器端回覆的封包

    f1.close()
    f2.close()

    ###########################################################
    # 取出 ContentType 為 22 == 0x16 的 Handshake 訊息
    handshake_msgs_result = b''
    shandshake_msgs_result = b''
    while len(content1) > 0:
        typ, ver1, ver2, len1, len2 = content1[:5]
        length = (len1 * 256) + len2
        fragmt = content1[5:5 + length]
        tail = content1[5 + length:]
        if typ == 22:
            handshake_msgs_result += fragmt
        content1 = tail
    ###########################################################
    # 取出 ContentType 為 22 == 0x16 的 Handshake 訊息
    while len(content2) > 0:
        typ, ver1, ver2, len1, len2 = content2[:5]
        length = (len1 * 256) + len2
        fragmt = content2[5:5 + length]
        tail = content2[5 + length:]
        if typ == 22:
            shandshake_msgs_result += fragmt
        content2 = tail
    ###########################################################
    cli_random = b''
    ser_random = b''
    encrypted_pre_master_secret = b''
    ###########################################################
    # 從 ClientHello 訊息擷取出 32 bytes 的 client_random
    while len(handshake_msgs_result) > 0:
        typ, len1, len2, len3 = handshake_msgs_result[:4]
        length = (len1 * 256 * 256) + (len2 * 256) + len3
        need = handshake_msgs_result[4:4 + length]
        tail = handshake_msgs_result[4 + length:]
        if typ == 1:
            cli_random += need[2:34]  # 32bytes
        if typ == 16:  # 從 ClientKeyExchange 訊息擷取出 encrypted_pre_master_secret
            encrypted_pre_master_secret += need[2:length]

        handshake_msgs_result = tail
    ###########################################################
    # 從 ServerHello 訊息擷取出 32 bytes 的 server_random
    while len(shandshake_msgs_result) > 0:
        typ, len1, len2, len3 = shandshake_msgs_result[:4]
        length = (len1 * 256 * 256) + (len2 * 256) + len3
        need = shandshake_msgs_result[4:4 + length]
        tail = shandshake_msgs_result[4 + length:]
        if typ == 2:
            ser_random += need[2:34]  # 32bytes

        shandshake_msgs_result = tail
    ###########################################################
    print("client_random =")
    print(str(binascii.hexlify(cli_random).decode(encoding='utf-8')))

    print("server_random =")
    print(str(binascii.hexlify(ser_random).decode(encoding='utf-8')))

    print("encrypted_pre_master_secret =")
    print(str(binascii.hexlify(encrypted_pre_master_secret).decode(encoding='utf-8')))
    ###########################################################
    # 利用 RSA private key 解密，算出 48 bytes 的 pre_master_secret
    pre_master_secret = RSA_DECRYPT(in3, encrypted_pre_master_secret)
    print("pre_master_secret =")
    print(str(binascii.hexlify(pre_master_secret).decode(encoding='utf-8')))

    ###########################################################
    # 利用 TLS PRF 函式，從 pre_master_secret 算出 48 bytes 的 master_secret
    a = b'master secret'
    b = b'key expansion'
    master_secret = TLS_PRF(pre_master_secret, a, cli_random + ser_random, 48)
    print("master_secret =")
    print(str(binascii.hexlify(master_secret).decode(encoding='utf-8')))
    ###########################################################
    # 利用 TLS PRF 函式，從 master_secret 算出 master_secret
    result_master_secret = TLS_PRF(master_secret, b, ser_random + cli_random, 104)
    client_write_MAC_key = result_master_secret[:20]
    server_write_MAC_key = result_master_secret[20:40]
    client_write_key = result_master_secret[40:56]
    server_write_key = result_master_secret[56:72]
    client_write_iv = result_master_secret[72:88]
    server_write_iv = result_master_secret[88:104]

    print("client_write_key = " + str(binascii.hexlify(client_write_key).decode(encoding='utf-8')))
    print("server_write_key = " + str(binascii.hexlify(server_write_key).decode(encoding='utf-8')))
    ###########################################################
    # 從封包檔案包含的那些 records 取出 ContentType 為 23 == 0x17 的 ApplicationData 訊息，它們目前是 AES-128-CBC 加密的狀態
    ApplicationData = b''
    while len(content3) > 0:
        typ, ver1, ver2, len1, len2 = content3[:5]
        length = (len1 * 256) + len2
        fragmt = content3[5:5 + length]
        tail = content3[5 + length:]
        if typ == 23:
            ApplicationData += fragmt
        content3 = tail

    # 將這些 ApplicationData 訊息利用 client_write_key 以 AES-128-CBC 解密。
    final_result = AES128CBC_DECRYPT(client_write_key, client_write_iv, ApplicationData)

    padding_length = final_result[-1]
    content = final_result[16:-1 - padding_length - 20]
    strcontent = str(content.decode(encoding='utf-8'))
    o1.write(strcontent)  # 將明文的 HTTP request/response 訊息分別寫入輸出檔案。
    o1.close()

    ###########################################################
    # 從封包檔案包含的那些 records 取出 ContentType 為 23 == 0x17 的 ApplicationData 訊息，它們目前是 AES-128-CBC 加密的狀態
    sApplicationData = b''
    while len(content4) > 0:
        typ, ver1, ver2, len1, len2 = content4[:5]
        length = (len1 * 256) + len2
        fragmt = content4[5:5 + length]
        tail = content4[5 + length:]
        if typ == 23:
            sApplicationData += fragmt
        content4 = tail
###########################################################
    # 將這些 ApplicationData 訊息利用 server_write_key以 AES-128-CBC 解密。
    sfinal_result = AES128CBC_DECRYPT(server_write_key, server_write_iv, sApplicationData)
    #print(sfinal_result)
    print(len(sfinal_result))##416
    fresult = b''
    while len(sfinal_result) > 0:
        scontent = sfinal_result[16:382]
        tail = sfinal_result[415:]
        fresult += scontent 
        sfinal_result = tail
	
    print(len(fresult))##366
    print(binascii.hexlify(fresult))
    #print(fresult)

    strscontent = str(fresult)
    o2.write(strscontent)  # 將明文的 HTTP request/response 訊息分別寫入輸出檔案。
    o2.close()

    """# 將這些 ApplicationData 訊息利用 server_write_key以 AES-128-CBC 解密。
    sfinal_result = AES128CBC_DECRYPT(server_write_key, server_write_iv, sApplicationData)

    spadding_length = sfinal_result[-1]
    scontent = sfinal_result[16:-1 - spadding_length - 20]
    strscontent = str(scontent.decode(encoding='utf-8'))
    o2.write(strscontent)  # 將明文的 HTTP request/response 訊息分別寫入輸出檔案。
    o2.close()"""


main()
