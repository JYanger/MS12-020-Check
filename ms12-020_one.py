#!/usr/bin/env Python
# coding=utf-8
#https://github.com/JYanger

import socket
import struct
import sys
import os,time
import binascii
import ctypes

#ports = ['3389']
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE= -11
STD_ERROR_HANDLE = -12
FOREGROUND_BLACK = 0x0
FOREGROUND_WRITE = 0x07 # text color contains blue.  07亮白色
FOREGROUND_GREEN= 0x02 # text color contains green. 02 绿色
FOREGROUND_RED = 0x04 # text color contains red.     04红色
FOREGROUND_INTENSITY = 0x08 # text color is intensified. 字体颜色加强
class Color:
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    def set_cmd_color(self, color, handle=std_out_handle):
        bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
        return bool
    def reset_color(self):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_WRITE)
    def print_red_text(self, print_text):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_green_text(self, print_text):
        self.set_cmd_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_write_text(self, print_text):
        self.set_cmd_color(FOREGROUND_WRITE | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()

socket.setdefaulttimeout(5)

def rdp_check(HOST,PORT):
    buf=""
    buf+="\x03\x00"    # TPKT Header version 03, reserved 0
    buf+="\x00\x0b"    # Length
    buf+="\x06"        # X.224 Data TPDU length
    buf+="\xe0"        # X.224 Type (Connection request)
    buf+="\x00\x00"    # dst reference
    buf+="\x00\x00"    # src reference
    buf+="\x00"        # class and options
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST,PORT))
        s.send(buf)
        rec = s.recv(100).encode('hex')
        s.close()
        if "0300000b06d00000123400"  in rec:
            #print "Target is rdp, please wait for check"
            return 1
        else :
            #print "Target is not rdp!!!"
            return 0
    except Exception as e:
        pass

def rdp_ms12_020_check(HOST,PORT):
    
    col = Color()

    buf=""
    buf+="\x03\x00"    # TPKT Header version 03, reserved 0
    buf+="\x00\x0b"    # Length
    buf+="\x06"        # X.224 Data TPDU length
    buf+="\xe0"        # X.224 Type (Connection request)
    buf+="\x00\x00"    # dst reference
    buf+="\x00\x00"    # src reference
    buf+="\x00"        # class and options

    buf1=""                   # connect_initial
    buf1+="\x03\x00\x00\x65"  # TPKT Header
    buf1+="\x02\xf0\x80"      # Data TPDU, EOT
    buf1+="\x7f\x65\x5b"      # Connect-Initial
    buf1+="\x04\x01\x01"      # callingDomainSelector
    buf1+="\x04\x01\x01"      # callingDomainSelector
    buf1+="\x01\x01\xff"      # upwardFlag
    buf1+="\x30\x19"          # targetParams + size
    buf1+="\x02\x01\x22"      # maxChannelIds
    buf1+="\x02\x01\x20"      # maxUserIds
    buf1+="\x02\x01\x00"      # maxTokenIds
    buf1+="\x02\x01\x01"      # numPriorities
    buf1+="\x02\x01\x00"      # minThroughput
    buf1+="\x02\x01\x01"      # maxHeight
    buf1+="\x02\x02\xff\xff"  # maxMCSPDUSize
    buf1+="\x02\x01\x02"      # protocolVersion
    buf1+="\x30\x18"          # minParams + size
    buf1+="\x02\x01\x01"      # maxChannelIds
    buf1+="\x02\x01\x01"      # maxUserIds
    buf1+="\x02\x01\x01"      # maxTokenIds
    buf1+="\x02\x01\x01"      # numPriorities
    buf1+="\x02\x01\x00"      # minThroughput
    buf1+="\x02\x01\x01"      # maxHeight
    buf1+="\x02\x01\xff"      # maxMCSPDUSize
    buf1+="\x02\x01\x02"      # protocolVersion
    buf1+="\x30\x19"          # maxParams + size
    buf1+="\x02\x01\xff"      # maxChannelIds
    buf1+="\x02\x01\xff"      # maxUserIds
    buf1+="\x02\x01\xff"      # maxTokenIds
    buf1+="\x02\x01\x01"      # numPriorities
    buf1+="\x02\x01\x00"      # minThroughput
    buf1+="\x02\x01\x01"      # maxHeight
    buf1+="\x02\x02\xff\xff"  # maxMCSPDUSize
    buf1+="\x02\x01\x02"      # protocolVersion
    buf1+="\x04\x00"          # userData

    buf2=""                   # user_request
    buf2+="\x03\x00"          # header
    buf2+="\x00\x08"          # length
    buf2+="\x02\xf0\x80"      # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
    buf2+="\x28"              # PER encoded PDU contents

    buf3=""                   #channel_request
    buf3+="\x03\x00\x00\x0c"
    buf3+="\x02\xf0\x80\x38"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST,PORT))
        s.send(buf)
        rec1 = s.recv(1024).encode('hex')
        #print rec1
        
        s.send(buf1)
        s.send(buf2)
        rec2 = s.recv(1024).encode('hex')
        user1_16 = rec2[18]+rec2[19]+rec2[20]+rec2[21]
        user1_10 = list(str(int(user1_16)))           #将16进制转换成10进制，在转换为列表
        while len(''.join(user1_10))!=4:
            user1_10.insert(0,'0')
        user1_10 = ''.join(user1_10)
        chan1_16 = list(hex(int(user1_10)+int('1001')))
        chan1_16.remove(chan1_16[0])
        chan1_16.remove(chan1_16[0])
        while len(''.join(chan1_16))!=4:
            chan1_16.insert(0,'0')
        chan1_16 = ''.join(chan1_16)
        #chan1 = '03ea'
        #print rec2

        s.send(buf2)
        rec3 = s.recv(1024).encode('hex')
        user2_16 = rec3[18]+rec3[19]+rec3[20]+rec3[21]
        user2_10 = list(str(int(user2_16)))
        while len(''.join(user2_10))!=4:
            user2_10.insert(0,'0')
        user2_10 = ''.join(user2_10)
        chan2_16 = list(hex(int(user2_10)+int('1001')))
        chan2_16.remove(chan2_16[0])
        chan2_16.remove(chan2_16[0])
        while len(''.join(chan2_16))!=4:
            chan2_16.insert(0,'0')
        chan2_16 = ''.join(chan2_16)
        #chan2 = '03eb'
        #print rec3
        
        #check_code1 = str(binascii.b2a_hex(buf3))+user1+chan2
        check_code1 = binascii.a2b_hex(str(binascii.b2a_hex(buf3))+user1_16+chan2_16)  #发送16进制数据包
        s.send(check_code1)
        rec4 = s.recv(1024).encode('hex')
        #print rec4
        if rec4[14]+rec4[15]+rec4[16]+rec4[17] == "3e00":
            col.print_red_text("[+] "+HOST+":"+str(PORT)+" is valueable MS12-020!!!")
            check_code2 = str(binascii.b2a_hex(buf3))+user2+chan2
            check_code2 = binascii.a2b_hex(str(binascii.b2a_hex(buf3))+user2_16+chan2_16)
            s.send(check_code2)         #防止蓝屏
        else:
            col.print_green_text("[-] "+HOST+":"+str(PORT)+" is SAFE.")
        s.close()
    except Exception as e:
        #print 'error'
        pass

def run(HOST,PORT):
    if rdp_check(HOST,PORT)!=1:
        col.print_write_text("[-] "+HOST+":"+str(PORT)+" maybe is not valueable.")
    else:
        #print rdp_check(HOST,PORT)
        rdp_ms12_020_check(HOST,PORT)

if __name__=="__main__":
    col = Color()
    if len(sys.argv)!=3:
        col.print_write_text("e.g: python2 "+os.path.basename(sys.argv[0])+" [ip] "+"[port]")
    else:
        run(str(sys.argv[1]),int(sys.argv[2]))
