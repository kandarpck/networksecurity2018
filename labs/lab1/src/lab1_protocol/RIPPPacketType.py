from enum import Enum, unique


# 0 = SYN
# 1 = ACK
# 2 = SYN-ACK
# 3 = DATA
# 4 = FIN
# 5 = FIN-ACK

@unique
class RIPPPacketType(Enum):
    SYN = 0
    ACK = 1
    SYN_ACK = 2
    DATA = 3
    FIN = 4
    FIN_ACK = 5


packet_type_mapping = ['SYN', 'ACK', 'SYN-ACK', 'Data', 'FIN', 'FIN-ACK']

max_seq_no = 2147483647
