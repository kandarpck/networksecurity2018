from enum import Enum, unique


# 0 = SYN
# 1 = ACK
# 2 = SYNACK
# 3 = DATA
# 4 = FIN

@unique
class RIPPPacketType(Enum):
    SYN = 'SYN'
    ACK = 'ACK'
    SYN_ACK = 'SYNACK'
    DATA = 'Data'
    FIN = 'FIN'


@unique
class StateType(Enum):
    LISTEN = 'LISTEN'
    SYN_SENT = 'SYN-SENT'
    SYN_RECEIVED = 'SYN-RECEIVED'
    ESTABLISHED = 'ESTABLISHED'
    CLOSING = 'CLOSING'
    CLOSED = 'CLOSED'


packet_type_mapping = ['SYN', 'ACK', 'SYNACK', 'Data', 'FIN', 'FINACK']

max_seq_no = 2147483647
