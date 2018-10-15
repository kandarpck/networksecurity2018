from enum import Enum, unique


# 0 = SYN
# 1 = ACK
# 2 = SYN-ACK
# 3 = DATA
# 4 = FIN
# 5 = FIN-ACK

@unique
class RIPPPacketType(Enum):
    SYN = 'SYN'
    ACK = 'ACK'
    SYN_ACK = 'SYNACK'
    DATA = 'Data'
    FIN = 'FIN'
    FIN_ACK = 'FINACK'


packet_type_mapping = ['SYN', 'ACK', 'SYNACK', 'Data', 'FIN', 'FINACK']

max_seq_no = 2147483647