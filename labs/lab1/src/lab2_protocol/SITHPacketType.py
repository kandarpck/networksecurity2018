from enum import Enum, unique


# 0 = SYN
# 1 = ACK
# 2 = SYNACK
# 3 = DATA
# 4 = FIN

@unique
class SITHPacketType(Enum):
    HELLO = 'HELLO'
    FINISH = 'FINISH'
    DATA = 'DATA'
    CLOSE = 'CLOSE'


@unique
class StateType(Enum):
    LISTEN = 'LISTEN'
    SYN_SENT = 'SYN-SENT'
    SYN_RECEIVED = 'SYN-RECEIVED'
    ESTABLISHED = 'ESTABLISHED'
    CLOSING = 'CLOSING'
    CLOSED = 'CLOSED'


packet_type_mapping = ['HELLO', 'FINISH', 'DATA', 'CLOSE']

max_seq_no = 2147483647
