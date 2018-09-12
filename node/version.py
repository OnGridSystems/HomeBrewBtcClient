# /**
#  * network protocol versioning
#  */

PROTOCOL_VERSION = 70015

# ! initial proto version, to be increased after version/verack negotiation
INIT_PROTO_VERSION = 209

# ! In this version, 'getheaders' was introduced.
GETHEADERS_VERSION = 31800

# ! disconnect from peers older than this proto version
MIN_PEER_PROTO_VERSION = GETHEADERS_VERSION

# ! nTime field added to CAddress, starting with this version
# ! if possible, avoid requesting addresses nodes older than this
CADDR_TIME_VERSION = 31402

# ! BIP 0031, pong message, is enabled for all versions AFTER this one
BIP0031_VERSION = 60000

# ! "filter*" commands are disabled without NODE_BLOOM after and including this version
NO_BLOOM_VERSION = 70011

# ! "sendheaders" command and announcing blocks with headers starts with this version
SENDHEADERS_VERSION = 70012

# ! "feefilter" tells peers to filter invs to you by fee starts with this version
FEEFILTER_VERSION = 70013

# ! short-id-based block download starts with this version
SHORT_IDS_BLOCKS_VERSION = 70014

# ! not banning for invalid compact blocks starts with this version
INVALID_CB_NO_BAN_VERSION = 70015
