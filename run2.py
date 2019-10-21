import settings
settings.WARNING_ADDRESS = 0x14b28
settings.VERBOSE = False
settings.TARGET_ADDRESS = 0x14660
settings.TARGET_FUNCTION = "crypto_stream_salsa20_xor"
settings.TARGET_BINARY = "/home/roeland/Documents/tweetnacl/tweetnaclARMO3NoInline"
settings.messagelength = 2
settings.noncePointer = -300
settings.params = [settings.outputBufferPointer, settings.pointerToMessage, settings.messagelength, settings.noncePointer, settings.pointerToKey]
settings.secret = settings.key.concat(settings.message)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
import tool