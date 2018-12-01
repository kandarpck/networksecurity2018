from enum import Enum, unique


# 0 = HELLO
# 1 = FINISH
# 2 = DATA
# 3 = CLOSE

@unique
class SITHPacketType(Enum):
    HELLO = 'HELLO'
    FINISH = 'FINISH'
    DATA = 'DATA'
    CLOSE = 'CLOSE'


@unique
class StateType(Enum):
    LISTEN = 'LISTEN'
    HELLO_SENT = 'HELLO-SENT'
    HELLO_RECEIVED = 'HELLO-RECEIVED'
    ESTABLISHED = 'ESTABLISHED'
    CLOSING = 'CLOSING'
    CLOSED = 'CLOSED'


packet_type_mapping = ['HELLO', 'FINISH', 'DATA', 'CLOSE']
