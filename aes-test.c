#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "hex-dump.h"
#include "virt-to-phys.h"

#define AES_REGISTER_BASE 0x38c00000

// A mix between `FCINTSTAT` and `AES_Status`?
#define AES_REGISTER_CONTROL AES_REGISTER_BASE + 0x00

// Appears to begin the AES operation? Maybe?
#define AES_REGISTER_GO AES_REGISTER_BASE + 0x04
// 0x1 is written to it to when using the fourth key (0x3, 0b11).
// Its value appears to be checked for to be zero after write.
// However, writing zero to it appears to allow usage again.
#define AES_REGISTER_KEY_UNKNOWN AES_REGISTER_BASE + 0x08
#define AES_REGISTER_STATUS AES_REGISTER_BASE + 0x0c
// Seemingly unused.
#define AES_REGISTER_UNKNOWN_1 AES_REGISTER_BASE + 0x10
#define AES_REGISTER_KEY_CONTROL_TEST AES_REGISTER_BASE + 0x14

#define AES_REGISTER_OUT_SIZE AES_REGISTER_BASE + 0x18
// This appears to not do anything. Any values written to it are seemingly ignored.
#define AES_REGISTER_OUT_UNUSED AES_REGISTER_BASE + 0x1c
#define AES_REGISTER_OUT_ADDRESS AES_REGISTER_BASE + 0x20

#define AES_REGISTER_IN_SIZE AES_REGISTER_BASE + 0x24
#define AES_REGISTER_IN_ADDRESS AES_REGISTER_BASE + 0x28

// Referred to as "aux" - what is this?
#define AES_REGISTER_AUX_SIZE AES_REGISTER_BASE + 0x2c
#define AES_REGISTER_AUX_ADDR AES_REGISTER_BASE + 0x30
// Why is the size present twice?
#define AES_REGISTER_ADDITIONAL_SIZE AES_REGISTER_BASE + 0x34

// TODO: What are these?
#define AES_REGISTER_UNKNOWN_2 AES_REGISTER_BASE + 0x38
#define AES_REGISTER_UNKNOWN_3 AES_REGISTER_BASE + 0x3c
#define AES_REGISTER_UNKNOWN_4 AES_REGISTER_BASE + 0x40
#define AES_REGISTER_UNKNOWN_5 AES_REGISTER_BASE + 0x44
#define AES_REGISTER_UNKNOWN_6 AES_REGISTER_BASE + 0x48

// XXX: This seems to be useful for 256-bit AES keys.
#define AES_REGISTER_KEY1 AES_REGISTER_BASE + 0x4c
#define AES_REGISTER_KEY2 AES_REGISTER_BASE + 0x50
// XXX: This appears to be useful for 192-bit AES keys.
#define AES_REGISTER_KEY3 AES_REGISTER_BASE + 0x54
#define AES_REGISTER_KEY4 AES_REGISTER_BASE + 0x58
// XXX: This appears to be useful for 128-bit AES keys.
#define AES_REGISTER_KEY5 AES_REGISTER_BASE + 0x5c
#define AES_REGISTER_KEY6 AES_REGISTER_BASE + 0x60
#define AES_REGISTER_KEY7 AES_REGISTER_BASE + 0x64
#define AES_REGISTER_KEY8 AES_REGISTER_BASE + 0x68

#define AES_REGISTER_KEY_TYPE AES_REGISTER_BASE + 0x6c
#define AES_REGISTER_OPERATION_UNKNOWN AES_REGISTER_BASE + 0x70

#define AES_REGISTER_IV1 AES_REGISTER_BASE + 0x74
#define AES_REGISTER_IV2 AES_REGISTER_BASE + 0x78
#define AES_REGISTER_IV3 AES_REGISTER_BASE + 0x7c
#define AES_REGISTER_IV4 AES_REGISTER_BASE + 0x80

// What happened to 0x84?
#define AES_REGISTER_UKNOWN_UNUSED_1 AES_REGISTER_BASE + 0x84

// ???
#define AES_REGISTER_KEY_TYPE_AGAIN AES_REGISTER_BASE + 0x88

// Our global memory.
uint32_t *aes_mem = NULL;

// Writes to a location in memory. Assumes the address is 0x38c00000 to 0x38c00100 (0x100 bytes).
void write_uint32(uint32_t register_offset, uint32_t value) {
    if (register_offset < AES_REGISTER_BASE || register_offset > (AES_REGISTER_BASE + 0x100)) {
        printf("Invalid write to 0x%08x!", register_offset);
        exit(-1);
    }

    uint32_t adjusted_offset = register_offset - AES_REGISTER_BASE;
    uint32_t mmap_array_index = adjusted_offset / 4;
    aes_mem[mmap_array_index] = value;
}

// Reads a uint32_t from memory. Assumes the value is 0x38c00000 to 0x38c00100 (0x100 bytes).
uint32_t read_uint32(uint32_t register_offset) {
    if (register_offset < AES_REGISTER_BASE || register_offset > (AES_REGISTER_BASE + 0x100)) {
        printf("Invalid read from 0x%08x!", register_offset);
        exit(-1);
    }

    uint32_t adjusted_offset = register_offset - AES_REGISTER_BASE;

    // However, this is an array of uint32_ts - the actual address is divided by sizeof(uint32_t), or 4.
    uint32_t mmap_array_index = adjusted_offset / 4;
    return (uint32_t)aes_mem[mmap_array_index];
}

// Outputs the value of the current register, along with its bits.
void dump_register(uint32_t current_value) {
    printf("%08x (", current_value);
    for (int current_bit = 32; current_bit > 0; current_bit -= 8) {
        // Add a space between groups of bits.
        if (current_bit != 32) {
            printf(" ");
        }

        for (int bit_offset = 0; bit_offset < 8; bit_offset++) {
            int shifted_value = 1 << (current_bit - bit_offset - 1);
            bool has_bit = (current_value & shifted_value) == shifted_value;

            printf("%d", has_bit ? 1 : 0);
        }
    }
    printf(")\n");
}

// Dumps 0x90 bytes.
void dump_mem() {
    printf("Dumping:\n");
    for (size_t i = 0; i < 0x90; i += 0x4) {
        uint32_t current_offset = AES_REGISTER_BASE + i;
        uint32_t current_value = read_uint32(current_offset);
        printf("%08x => ", current_offset);

        // List bits
        dump_register(current_value);
    }
}

#pragma mark - AAAAA

// [1:0] Key type
//
// 00 - custom key
// 01 - GID key, ignores custom key
// 10 - ???
// 11 - ???
// Any bits set above those two appear to be ignored.
#define AES_KEY_TYPE_CONTENTS 0b00

uint32_t key_control_contents() {
    return
        // [31:6] Not functional, seemingly.
        (1 << 31) + (1 << 30) + (1 << 29) + (1 << 28) +
        (1 << 27) + (1 << 26) + (1 << 25) + (1 << 24) +
        (1 << 23) + (1 << 22) + (1 << 21) + (1 << 20) +
        (1 << 19) + (1 << 18) + (1 << 17) + (1 << 16) +
        (1 << 15) + (1 << 14) + (1 << 13) + (1 << 12) +
        (1 << 11) + (1 << 10) + (1 << 9)  + (1 << 8)  +
        (1 << 7)  + (1 << 6) +
        // [5:4] Key size
        //
        // 00 => 128-bit
        // 01 => 192-bit
        // 10 => 256-bit
        // 11 => ??? behaves like 256-bit
        (0 << 5) + (0 << 4) +
        // [3:2] Operation
        //
        // 00 => ??? looks like ECB
        // 01 => ECB
        // 10 => CBC
        // 11 => CTR
        (1 << 3) + (0 << 2) +
        // [1] Seemingly ignored, or not functional?
        // It appears to be set within the iPod's firmware, so it must have some meaning.
        (1 << 1) +
        // [0] Mode
        //
        // 0 => Decrypt
        // 1 => Encrypt
        (1 << 0);
}

void setup_aes_key() {
    // To clear the 256-bit half:
    // write_uint32(AES_REGISTER_KEY1, 0);
    // write_uint32(AES_REGISTER_KEY2, 0);
    // and the 192-bit half:
    // write_uint32(AES_REGISTER_KEY3, 0);
    // write_uint32(AES_REGISTER_KEY4, 0);
    // lastly, for the 128-bit half:
    // write_uint32(AES_REGISTER_KEY5, 0);
    // write_uint32(AES_REGISTER_KEY6, 0);
    // write_uint32(AES_REGISTER_KEY7, 0);
    // write_uint32(AES_REGISTER_KEY8, 0);

    // Set our testing key, 02418105 dfb3be2a f2a76248 e026f702:
    // Note that the  
    write_uint32(AES_REGISTER_KEY5, 0x05814102);
    write_uint32(AES_REGISTER_KEY6, 0x2abeb3df);
    write_uint32(AES_REGISTER_KEY7, 0x4862a7f2);
    write_uint32(AES_REGISTER_KEY8, 0x02f726e0);

    // Set an empty IV.
    write_uint32(AES_REGISTER_IV1, 0);
    write_uint32(AES_REGISTER_IV2, 0);
    write_uint32(AES_REGISTER_IV3, 0);
    write_uint32(AES_REGISTER_IV4, 0);
}

static unsigned char in_data[64] = "";
static unsigned char out_data[64] = "";

int main() {
    // As described in https://stackoverflow.com/a/12041352
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);

    // 0x38c00000 (AES_REGISTER_BASE) is definitely a multiple of the page size,
    // so we'll use it directly.
    //
    // We'll map about 0x100 in, just because we can. I have no clue what its true size is.
    aes_mem = mmap(NULL, 0x100, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, AES_REGISTER_BASE);
    if (aes_mem == MAP_FAILED) {
        printf("Can't map memory\n");
        exit(-1);
    }

    // Apparently we must read and write this for various lazy allocation reasons.
    strcpy(in_data, "Hello, world!");
    strcpy(out_data, "");

    // We'll now obtain the physical addresses of our buffers.
    uintptr_t phys_out_addr = virt_to_phys_user("out_buf", (uintptr_t)&out_data);
    uintptr_t phys_in_addr = virt_to_phys_user("in_buf", (uintptr_t)&in_data);

    // As performed by 0x0818ea44 ("AESHardwareDecryptEncrypt") within firmware 1.0.2 for the iPod nano 5th gen:
    printf("Prior to preparation:\n");

    // TODO: What are these?
    // write_uint32(AES_REGISTER_UNKNOWN_2, 0);
    // write_uint32(AES_REGISTER_UNKNOWN_3, 0);
    // write_uint32(AES_REGISTER_UNKNOWN_4, 0);
    write_uint32(AES_REGISTER_UKNOWN_UNUSED_1, 0);
    // write_uint32(AES_REGISTER_UNKNOWN_6, 0);

    dump_mem();

    // // Called with non-custom keys (i.e. what we're doing).
    // // Writing 1 appears to halt functionality, and 0 seems to have it resume.
    // //
    // // TODO: That's... wrong. What is the right approach?
    // write_uint32(AES_REGISTER_KEY_UNKNOWN, 0);
    // write_uint32(AES_REGISTER_KEY_UNKNOWN, 1);
    // uint32_t current_status = read_uint32(AES_REGISTER_KEY_UNKNOWN);
    // printf("Preparation value: ");
    // dump_register(current_status);
    // write_uint32(AES_REGISTER_KEY_UNKNOWN, 0);

    // TODO: What is this register?
    // Possibly flush, or reset to zero?
    write_uint32(AES_REGISTER_OPERATION_UNKNOWN, 0b001);
    // Let's not specify a custom key, just for testing.
    write_uint32(AES_REGISTER_KEY_TYPE, AES_KEY_TYPE_CONTENTS);
    // This is read, and... written within firmware? Reading does not appear to be necessary.
    uint32_t weird_key_type_value = read_uint32(AES_REGISTER_KEY_TYPE);
    printf("Key type: ");
    dump_register(weird_key_type_value);
    write_uint32(AES_REGISTER_KEY_TYPE_AGAIN, ~weird_key_type_value);

    // After control is set to 1, it appears the actual setup begins.
    // TODO: What exactly does this control?
    write_uint32(AES_REGISTER_CONTROL, 1);

    // See the comments within key_control_contents for guessed structure.
    write_uint32(AES_REGISTER_KEY_CONTROL_TEST, key_control_contents());

    // Our output data is only used in two registers.
    write_uint32(AES_REGISTER_OUT_SIZE, 64);
    write_uint32(AES_REGISTER_OUT_ADDRESS, phys_out_addr);

    // Meanwhile, input appears to be both in its own, and auxilary.
    write_uint32(AES_REGISTER_IN_SIZE, 64);
    write_uint32(AES_REGISTER_IN_ADDRESS, phys_in_addr);
    // What exactly is auxilary?
    write_uint32(AES_REGISTER_AUX_SIZE, 64);
    write_uint32(AES_REGISTER_AUX_ADDR, phys_in_addr);
    // What is this additional size?
    write_uint32(AES_REGISTER_ADDITIONAL_SIZE, 64);

    setup_aes_key();

    printf("About to encrypt...\n");
    dump_mem();

    // TODO: Determine bit fields for status. It's set to 7 within firmware, but 6 within bootrom.
    // It seems it really only needs to be one...
    write_uint32(AES_REGISTER_STATUS, 7);
    write_uint32(AES_REGISTER_GO, 1);

    bool running = true;
    while (running) {
        uint32_t current_status = read_uint32(AES_REGISTER_STATUS);
        printf("Current status: ");
        dump_register(current_status);

        if ((current_status & 1) == 0) {
            running = false;
        }
    }

    usleep(100);

    // TODO: What exactly does this do?
    write_uint32(AES_REGISTER_CONTROL, 0);

    printf("Finished encrypting!\n");
    dump_mem();

    hexDump("input buf", &in_data, 64, 16);
    hexDump("output buf", &out_data, 64, 16);

    return 0;
}
