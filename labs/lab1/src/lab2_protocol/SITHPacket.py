import hashlib

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BUFFER, STRING

from .SITHPacketType import SITHPacketType, packet_type_mapping


class SITHPacket(PacketType):
    DEFINITION_IDENTIFIER = "SITH.kandarp.packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

        ("Type", STRING), # HELLO, FINISH, DATA, CLOSE
        ("Random", BUFFER),#({Optional: True})),
        ("PublicValue", BUFFER),#({Optional: True})),
        ("Certificate", BUFFER),#({Optional: True})),
        ("Signature", BUFFER),#({Optional: True})),
        ("Ciphertext", BUFFER)#({Optional: True}))

    ]
