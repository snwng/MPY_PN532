
from time import sleep_ms, ticks_ms, ticks_diff # pyright: ignore

_ACK = b"\x00\x00\xFF\x00\xFF\x00"
_NACK = b"\x00\x00\xFF\xFF\x00\x00"
_PN532_ADDR = 0x24
_PREAMBLE = 0x00
_POSTAMBLE = 0x00
_START_CODE_1 = 0x00
_START_CODE_2 = 0xFF
_TFI_H2M = 0xD4
_TFI_M2H = 0xD5

_CMD_GetFirmwareVersion = 0x02
_CMD_GetGeneralStatus = 0x04
_CMD_SAM_CONFIGURATION = 0x14
_CMD_PowerDown = 0x16
_CMD_InListPassiveTarget = 0x4A
_CMD_InDataExchange = 0x40

_MIFARE_AUTH_A = 0x60
_MIFARE_AUTH_B = 0x61
_MIFARE_READ = 0x30
_MIFARE_WRITE = 0xA0
_MIFARE_INCREMENT = 0xC1
_MIFARE_DECREMENT = 0xC0

KEY_A = 0x00
KEY_B = 0x01


class PN532:

    def __init__(self, i2c, debug=False):
        self.i2c = i2c
        self.debug = debug
        self.pow_down = False

    def write_rawdata(self, data):
        return self.i2c.writeto(_PN532_ADDR, data)

    def read_rawdata(self, n=6, retries=6, retry_delay=10):
        for _ in range(retries):
            try:
                return self.i2c.readfrom(_PN532_ADDR, n)
            except OSError:
                if self.debug: print("reading failed, retrying ...")
                sleep_ms(retry_delay)
        raise OSError("Read failed after retries")

    def read_frame(self, n=32):
        if self.debug: print("Reading frame ...")
        res = self.read_rawdata(n + 8)
        if self.debug: print(f" received frame: {res.hex(" ")}\n")
        if res[0] != 0x01:
            raise OSError("Not ready")
        if res[1] != _PREAMBLE or res[2] != _START_CODE_1 or res[3] != _START_CODE_2:
            raise OSError("Invalid response")
        l = res[4]
        lcs = res[5]
        if (l + lcs) & 0xFF != 0x00:
            raise OSError("Length checksum doesn't match")
        if n < l:
            raise OSError("Frame not read completely")
        if res[6] != _TFI_M2H or res[l + 7] != 0x00:
            raise OSError("Invalid response")
        if sum(res[6:l + 7]) & 0xFF != 0x00:
            raise OSError("Data checksum doesn't match")
        return res[7:l + 6]

    def wait_ready(self, timeout=1000, retry_delay=5):
        if self.debug: print("Waiting for device to be ready ...")
        timestamp = ticks_ms()
        while timeout is None or ticks_diff(ticks_ms(), timestamp) < timeout:
            try:
                sleep_ms(retry_delay)
                r = self.read_rawdata(1)
                if r and r[0] == 0x01:
                    return
                if self.debug: print("Device is not ready, retrying ...")
            except OSError:
                pass
        raise OSError("Waiting timeout exceeded")

    def write_cmd(self, cmd, params=None):
        data = bytes([_TFI_H2M, cmd & 0xFF])
        if params is not None:
            data += bytes([p & 0xFF for p in params])

        l = len(data)
        lcs = 0xFF - l + 1
        dcs = (0xFF - sum(data) + 1) & 0xFF
        frame = bytes([_PREAMBLE, _START_CODE_1, _START_CODE_2, l, lcs]) + data + bytes([dcs, _POSTAMBLE])
        if self.debug: print(f" Frame sent :{frame.hex(" ")}")
        self.write_rawdata(frame)
        self.wait_ready()
        ack = self.read_rawdata(len(_ACK) + 1)
        if ack != b"\x01" + _ACK:
            raise OSError("No ack received")

    def firmware_version(self):
        if self.debug: print("Getting firmware version ...")
        self.write_cmd(_CMD_GetFirmwareVersion)
        self.wait_ready()
        data = self.read_frame()
        if data[0] != _CMD_GetFirmwareVersion + 1:
            raise OSError("Invalid response")
        if self.debug: print(f"Firmware version:{data[1:].hex(" ")}")
        return data[1:].hex(" ")

    def general_status(self):
        if self.debug: print("Getting general status ...")
        self.write_cmd(_CMD_GetGeneralStatus)
        self.wait_ready()
        res = self.read_frame()
        if res[0] != _CMD_GetGeneralStatus + 1:
            raise OSError("Invalid response")
        tg = res[3]
        res = list(res)
        if tg == 0:
            res = res[1:]
        elif tg == 1:
            res = res[1:4] + [(res[4], res[5], res[6], res[7])] + res[8:]
        else:
            res = res[1:4] + [(res[4], res[5], res[6], res[7]), (res[8], res[9], res[10], res[11])] + res[12:]
        if self.debug: print(f"General status {res}")
        return res

    def set_mode(self, mode=0x01):
        if self.debug: print(f"Setting device mode to {mode} ...")
        self.write_cmd(_CMD_SAM_CONFIGURATION, [mode, 0x00])
        self.wait_ready()
        res = self.read_frame()
        if res[0] != _CMD_SAM_CONFIGURATION + 1:
            raise OSError("Invalid response")

    def list_passive_target(self, timeout=3000):
        if self.debug: print("Listing Passive Targets ...")
        self.write_cmd(_CMD_InListPassiveTarget, [0x01, 0x00])
        try:
            self.wait_ready(timeout)
        except OSError:
            self.abort_cmd()
            raise OSError("Timeout exceeded")
        res = self.read_frame()
        if res[0] != _CMD_InListPassiveTarget + 1:
            raise OSError("Invalid response")
        if res[1] != 0x01:
            raise OSError("More than one card detected")
        uid_len = res[6]
        if uid_len > 7:
            raise OSError("The card's UID is too long")
        return [res[2], int.from_bytes(res[3:5]), res[5], list(res[7:7 + uid_len])]

    def mifare_classic_auth(self, uid, tg, key, key_type, block):
        if self.debug: print(f"Mifare authentification with key {key} on block {block} ...")
        param = [0] * 13
        param[0] = tg
        if key_type == KEY_A:
            param[1] = _MIFARE_AUTH_A
        elif key_type == KEY_B:
            param[1] = _MIFARE_AUTH_B
        else:
            raise OSError("Invalid key type")
        param[2] = block
        param[3:9] = key
        param[9:13] = uid
        self.write_cmd(_CMD_InDataExchange, param)
        self.wait_ready()
        res = self.read_frame(3)
        if res[0] != _CMD_InDataExchange + 1:
            raise OSError("Invalid response")
        if res[1] & 0x3F != 0x00:
            raise OSError("Command failed")

    def mifare_classic_read(self, tg, block):
        if self.debug: print(f"Reading from block {block} ...")
        self.write_cmd(_CMD_InDataExchange, [tg, _MIFARE_READ, block])
        self.wait_ready()
        res = self.read_frame()
        if res[0] != _CMD_InDataExchange + 1:
            raise OSError("Invalid response")
        if res[1] & 0x3F != 0x00:
            raise OSError("Command failed")
        if self.debug: print(f"Data read: ")
        return res[2:18]

    def mifare_classic_write(self, tg, block, data):
        param = [0] * 19
        param[0] = tg
        param[1] = _MIFARE_WRITE
        param[2] = block
        if len(data) > 16:
            raise OSError("data length exceeds 16 bytes")
        else:
            param[3:19] = list(data) + [0x00] * (16 - len(data))
        self.write_cmd(_CMD_InDataExchange, param)
        self.wait_ready()
        res = self.read_frame()
        if res[0] != _CMD_InDataExchange + 1:
            raise OSError("Invalid response")
        if res[1] & 0x3F != 0x00:
            raise OSError("Command failed")

    def power_down(self, wakeup_causes=0x88):
        if self.debug: print("Putting Device into low power mode ...")
        self.write_cmd(_CMD_PowerDown, [wakeup_causes])
        self.wait_ready()
        res = self.read_frame()
        if res[0] != _CMD_PowerDown + 1:
            raise OSError("Invalid response")
        if res[1] & 0x3F != 0x00:
            raise OSError("Command failed")
        self.pow_down = True

    def wakeup(self):
        if self.debug: print("Waking up device ...")
        self.write_rawdata(_ACK)
        sleep_ms(50)
        self.pow_down = False

    def abort_cmd(self):
        if self.debug: print("Sending ACK to abort ...")
        self.write_rawdata(_ACK)
