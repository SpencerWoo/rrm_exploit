
#The directory of the enhanced hostapd
HOSTAPD_DIR = "/path/to/your/enhanced/hostapd-2.6/hostapd"

#The MAC address of the target
TARGET_MAC = "aa:bb:cc:aa:bb:cc"

#The interface broadcasting the attack access-point
INTERFACE = "YOUR_INTERFACE"

#Gives the AP time to send the frames so that it doesn't reject us
#when too many consecutive requests are made.
ACTION_FRAME_COOLDOWN_WINDOW = 50

#The number of seconds we'll give for the firmware to reboot (this is very generous)
FIRMWARE_REBOOT_DELAY = 10

#The MAC address of the access point
AP_MAC = "dd:ee:ff:dd:ee:ff"

#The maximal poll time, in seconds, while waiting for a response from the backdoor
MAX_READ_DWORD_POLL_TIME = 5

#The granularity between subsequent poll attempts (in seconds)
POLL_GRANULARITY = 0.1

#The maximal exploit attempts before giving up
MAX_ATTEMPTS = 10

