# S5L8730 AES Engine
While toying around with an iPod nano 5th generation, I was curious on if one could utilize the AES engine beyond AES-128-CBC (as present within its firmware and bootrom). Unfortunately, there appears to be very little documentation regarding its operation beyond an implementation for the original iPhone/iPod touch (mirroring its bootrom as well). (Further frustratingly, the [S5L8700X datasheet](<https://freemyipod.org/wiki/S5L8700_datasheet>) marks the AES engine at `0x38C00000` marked as "reserved" and provides no insight beyond that.) The following is some experimentation on this in case it helps anyone else researching.

It appears that the engine present in S5L8730 (and presumably earlier?) may be a modification of what Samsung put in their later S5P cores - very close to what's present in modern Exynos. Another Samsung SoC, the S5PV210, has support for its crypto engine in the [Linux kernel](<https://github.com/torvalds/linux/blob/7ba2090ca64ea1aa435744884124387db1fac70f/drivers/crypto/s5p-sss.c#L97>) and its datasheet can be found floating around. Based on such, the S5L8730's engine appears to be a vague mix of its "feed" and AES engines. However, unlike the S5PV210, the S5L8730's appears to be purely DMA, and there is no PKA (public key accelerator).

## Register Layout
Please feel free to pull request and create issues - by no means should this be taken as a source of truth; descriptions and meanings can/will be wrong :)

As follows is the guessed layout of register space, base `0x38C00000`. Some discussion proceeds these tables. Please do not consider these official names.
| Offset | Name                       | Notes                                |
|--------|----------------------------|---------------------------------------|
| 0x0    | `AES_REGISTER_CONTROL`     | Appears to control engine operation, possibly? Keys must be set up afterwards. |
| 0x4    | `AES_REGISTER_GO`          | Bit 0 controls operation; all others appear to be ignored. |
| 0x8    | [`AES_REGISTER_KEY_UNKNOWN`](#aes_register_key_unknown-0x08) | Bit 0 appears to block operation of the engine. |
| 0xc    | [`AES_REGISTER_STATUS`](#aes_register_status-0x0c)      | Presumably, at least? Its lowest three bits change throughout operation. Write those three bits to clear. |
| 0x10   | `AES_REGISTER_UNKNOWN_1`   | Seemingly unused. It appears to ignore all writes. |
| 0x14   | [`AES_REGISTER_SETUP`](#aes_register_setup-0x14)       | Configures the operation the engine should perform. |
| 0x18   | `AES_REGISTER_OUT_SIZE`    | The length of data to write to output. |
| 0x1c   | `AES_REGISTER_OUT_UNUSED`  | Seemingly unused. All writes are ignored. |
| 0x20   | `AES_REGISTER_OUT_ADDRESS` | The address of the output buffer. |
| 0x24   | `AES_REGISTER_IN_SIZE`     | The length of data to process. |
| 0x28   | `AES_REGISTER_IN_ADDRESS`  | The address of the input buffer. |
| 0x2c   | `AES_REGISTER_AUX_SIZE`    | Unclear on usage - its value must match `AES_REGISTER_IN_SIZE` or things break. |
| 0x30   | `AES_REGISTER_AUX_ADDRESS` | Unclear on usage - its value must match `AES_REGISTER_IN_ADDRESS` or things break. |
| 0x34   | `AES_REGISTER_ADDITIONAL_SIZE` | Unclear on usage - its value must also match `AES_REGISTER_IN_SIZE` or the engine will error. |
| 0x38   | `AES_REGISTER_UNKNOWN_2`   | Appears to have a value 0x12040 greater than `AES_REGISTER_OUT_ADDRESS`. Possibly address to next block in... some way? |
| 0x3c   | `AES_REGISTER_UNKNOWN_3`   | This is 0x40 greater than UNKNOWN_2 above - 0x12080 greater than the out address. |
| 0x40   | `AES_REGISTER_UNKNOWN_4`   | This is set to `1` if `AES_REGISTER_OUT_SIZE` is greater than `AES_REGISTER_IN_SIZE`. |
| 0x44   | `AES_REGISTER_UNKNOWN_5`   | Its value is often `00004040`. On error, its value may be `00054040`. |
| 0x48   | `AES_REGISTER_UNKNOWN_6`   | Always observed to be zero - unclear. |
| 0x4c   | `AES_REGISTER_KEY1`        | For 256-bit AES, begin writing the key here. |
| 0x50   | `AES_REGISTER_KEY2`        | [...] |
| 0x54   | `AES_REGISTER_KEY3`        | For 192-bit AES, begin writing the key here. |
| 0x58   | `AES_REGISTER_KEY4`        | [...] |
| 0x5c   | `AES_REGISTER_KEY5`        | For 128-bit AES, begin writing the key here. |
| 0x60   | `AES_REGISTER_KEY6`        | [...] |
| 0x64   | `AES_REGISTER_KEY7`        | [...] |
| 0x68   | `AES_REGISTER_KEY8`        | Lowest half of AES key. |
| 0x6c   | `AES_REGISTER_KEY_TYPE`    | The key type to utilize. Its value must be also written to `AES_REGISTER_KEY_TYPE_AGAIN` in an inverted form. |
| 0x70   | `AES_REGISTER_OPERATION_UNKNOWN` | ???? |
| 0x74   | `AES_REGISTER_IV1`         | Upper word of AES IV. |
| 0x78   | `AES_REGISTER_IV2`         | [...] |
| 0x7c   | `AES_REGISTER_IV3`         | [...] |
| 0x80   | `AES_REGISTER_IV4`         | [...] |
| 0x84   | `AES_REGISTER_UKNOWN_UNUSED_1` | Its value appears to reset to 0xf. It additionally appears to ignore writes. |
| 0x88   | `AES_REGISTER_KEY_TYPE_AGAIN` | The key type to utilize... again. Its value must be an inverted form of `AES_REGISTER_KEY_TYPE`. |

AES keys and IVs must be little-endian. Unlike later SoCs, there appears to be no byte swapping.

### AES_REGISTER_KEY_UNKNOWN (0x08)
Its usage is unknown. Setting its zeroth bit appears to halt engine operation - perhaps it denotes engine state?

Some notes on its usage:
 - Within the iPod nano BootROM, this register is polled until its fourth bit is cleared. Through observation, only three bits were ever set.
 - The retail firmware waits for the zeroth bit to be cleared.
 - Oddly, the EFI driver simply waits for 2000 us.

### AES_REGISTER_STATUS (0x0c)
Within its retail firmware and EFI driver, 0x7 is written to this prior to operation. The BootROM does not whatsoever. Its lowest bit is checked to ensure an operation has completed. It appears you must write the lowest bit to allow operation to continue.

| Bit    | Description               |
|--------|---------------------------|
| [31:5] | Seemingly unused. Ignores writes. |
| [4]    | Unknown; see above.       |
| [3]    | Unknown. Set by default.  |
| [2]    | Unknown. Set by default.  |
| [1]    | Whether an operation is ongoing. |

### AES_REGISTER_SETUP (0x14)
It's unclear on how to configure CTR. It appears to only produce valid output with AES-192-CTR and AES-256-CTR. (This may be wrong - please validate yourself.)

| Bit    | Description               |
|--------|---------------------------|
| [31:6] | Seemingly ignored. |
| [5:4]  | Specifies key size.<br><br>**00** => 128-bit<br>**01** => 192-bit<br>**10** => 256-bit<br>**11** => Also 256-bit(?) |       
| [3:2]  | Specifies AES mode.<br><br>**00** => ECB<br>**01** => Also ECB(?)<br>**10** => CBC<br>**11** => CTR |
| [1]    | Seemingly ignored - unsetting it appears to have no change, but it is set within iPod firmware. |
| [0]    | Whether to encrypt.<br><br>**0** => Decrypt<br>**1** => Encrypt |

### AES_REGISTER_KEY_TYPE_AGAIN (0x6c)
Its value must be the inverse (i.e. its value bitwise NOR'd), or the used key will not differ. Notably, this is 0xffffffff on error - could it possibly deal with error handling as well?
