from typing import Any, List, Optional, Tuple, Union

_ACK: bytes
_NACK: bytes
_PN532_ADDR: int
_PREAMBLE: int
_POSTAMBLE: int
_START_CODE_1: int
_START_CODE_2: int
_TFI_H2M: int
_TFI_M2H: int
_CMD_GetFirmwareVersion: int
_CMD_GetGeneralStatus: int
_CMD_SAM_CONFIGURATION: int
_CMD_PowerDown: int
_CMD_InListPassiveTarget: int
_CMD_InDataExchange: int
_MIFARE_AUTH_A: int
_MIFARE_AUTH_B: int
_MIFARE_READ: int
_MIFARE_WRITE: int
_MIFARE_INCREMENT: int
_MIFARE_DECREMENT: int

A: int
B: int
DEFAULT_KEYA: List[int]
DEFAULT_KEYB: List[int]

class PN532_I2C:
    i2c: Any
    debug: bool
    pow_down: bool

    def __init__(self, i2c: Any, debug: bool = False) -> None:
        """Initializes the PN532 object."""
        ...
    def write_rawdata(self, data: bytes) -> int:
        """Writes raw data to the I2C bus."""
        ...
    def read_rawdata(self, n: int = 6, retries: int = 6, retry_delay: int = 10) -> bytes:
        """Reads raw data from the I2C bus with retries."""
        ...
    def read_frame(self, n: int = 32) -> bytes:
        """Reads a complete data frame from the PN532."""
        ...
    def wait_ready(self, timeout: int = 1000, retry_delay: int = 5) -> bool:
        """Waits for the PN532 to be ready to receive a command."""
        ...
    def write_cmd(self, cmd: int, params: Optional[List[int]] = None) -> None:
        """Writes a command to the PN532."""
        ...
    def firmware_version(self) -> str:
        """Gets the firmware version of the PN532."""
        ...
    def general_status(self) -> List[Union[int, Tuple[int, int, int, int]]]:
        """Gets the general status of the PN532."""
        ...
    def set_mode(self, mode: int = 1) -> None:
        """Sets the SAM (Secure Access Module) configuration mode."""
        ...
    def list_passive_target(self, timeout: int = 3000) -> List[Union[int, List[int]]]:
        """Lists available passive NFC targets."""
        ...
    def mifare_classic_auth(self, uid: List[int], tg: int, key: List[int], key_type: int, block: int) -> None:
        """Authenticates a MIFARE Classic card block."""
        ...
    def mifare_classic_read(self, tg: int, block: int) -> bytes:
        """Reads a block from a MIFARE Classic card."""
        ...
    def mifare_classic_write(self, tg: int, block: int, data: bytes) -> None:
        """Writes data to a block on a MIFARE Classic card."""
        ...
    def power_down(self, wakeup_causes: int = 136) -> None:
        """Puts the PN532 into power-down mode."""
        ...
    def wakeup(self) -> None:
        """Wakes the PN532 from power-down mode."""
        ...
    def abort_cmd(self) -> None:
        """Aborts the current command."""
        ...
