from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BUFFER, STRING, LIST
from playground.network.packet.fieldtypes.attributes import Optional

from .SITHPacketType import SITHPacketType


class SITHPacket(PacketType):
    DEFINITION_IDENTIFIER = "SITH.kandarp.packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

        ("Type", STRING),  # HELLO, FINISH, DATA, CLOSE
        ("Random", BUFFER({Optional: True})),
        ("PublicValue", BUFFER({Optional: True})),
        ("Certificate", LIST(BUFFER)({Optional: True})),
        ("Signature", BUFFER({Optional: True})),
        ("Ciphertext", BUFFER({Optional: True}))

    ]

    def sith_hello(self, random, public_val, certs):
        hello = SITHPacket()
        hello.Type = SITHPacketType.HELLO.value
        hello.Random = random
        hello.PublicValue = public_val
        hello.Certificate = certs
        return hello

    def sith_finish(self, signature):
        finish = SITHPacket()
        finish.Type = SITHPacketType.FINISH.value
        finish.Signature = signature
        return finish

    def sith_data(self, ciphertext):
        data = SITHPacket()
        data.Type = SITHPacketType.DATA.value
        data.Ciphertext = ciphertext
        return data

    def sith_close(self, error=None):
        close = SITHPacket()
        close.Type = SITHPacketType.CLOSE.value
        close.Ciphertext = error
        return close


if __name__ == '__main__':
    pass
