from itertools import tee, islice, izip_longest
from binascii import unhexlify, hexlify
from struct import pack

import StringIO
import json

from . import BitcoinEncoding, target_unpack, reverse_hash, uint256_from_str, sha256d, get_hash_func
from .transaction import Transaction
from .dark import CMasterNodeVote, ser_vector


def pairwise(iterator):
    """ Returns pairs of items until none are left in either iterator. If the
    list is odd and the second iterator runs out None will be returned for
    second arg """
    a, b = tee(iterator)
    return izip_longest(islice(a, 0, None, 2), islice(b, 1, None, 2))

def merkleroot(iterator, be=False, hashes=False, hash_func=sha256d):
    """ When given an iterator producing Transaction objects or transaction
    hashes (set hash=True, send in big endian) this computes a MerkleRoot for
    the collection of transactions. Returned as big endian byte string by
    default with second parameter as size of iterator. Could be optimized to
    use the list in place, but thats a future job... 

    sbwdlihao:It seems transaction hashes should be in little endian, and return 
    a little byte string by default
    """
    # get the hashes of all the transactions
    if not hashes:
        # sbwdlihao:It seems should be t.hash beacause hash is little endian
        # h_list = [t.behash for t in iterator]
        h_list = [t.hash for t in iterator]
    else:
        h_list = iterator

    size = len(h_list)
    # build our tree by repeated halving of the list
    while len(h_list) > 1:
        h_list = [hash_func(h1 + (h2 or h1))
                  for h1, h2 in pairwise(h_list)]
    # return little endian
    if be:
        return h_list[0][::-1], size
    return h_list[0], size

def merklebranch(iterator, be=False, hashes=False, hash_func=sha256d):
    """ Similar to the above method, this instead generates a merkle branch
    for mining clients to quickly re-calculate the merkle root with minimum
    of re-hashes while chaning the coinbase extranonce. Big endian by default,
    change kwarg for little endian """
    def shamaster(h1, h2):
        if h1 is None:
            return None
        return hash_func(h1 + (h2 or h1))

    # put a placeholder in our level zero that pretends to be the coinbase
    if not hashes:
        # sbwdlihao:It seems should be t.hash beacause hash is little endian
        # h_list = [None] + [t.behash for t in iterator]
        h_list = [None] + [t.hash for t in iterator]
    else:
        h_list = [None] + list(iterator)
    branch = []

    # build each level of the tree and pull out the leftmost non-None
    while len(h_list) > 1:
        # left most is what will be recomputed, we want the one right of the
        # leftmost
        # sbwdlihao:It seems should turn over
        # if be:
        #     branch.append(h_list[1])
        # else:
        #     branch.append(h_list[1][::-1])
        if be:
            branch.append(h_list[1][::-1])
        else:
            branch.append(h_list[1])
        h_list = [shamaster(h1, h2) for h1, h2 in pairwise(h_list)]
    return branch

def from_merklebranch(branch_list, coinbase, be=False, hash_func=sha256d):
    """ Computes a merkle root from a branch_list and a coinbase hash. Assumes
    branch_list is a list of little endian byte arrays of hash values, as is
    returned by merklebranch by default. Coinbase is expected to be a
    Transaction object. """
    # sbwdlihao:It seems should be coinbase.hash beacause hash is little endian
    # root = coinbase.behash
    root = coinbase.hash
    for node in branch_list:
        root = hash_func(root + node)

    # return be if requested
    if be:
        return root[::-1]
    return root


class BlockTemplate(BitcoinEncoding):
    """ An object for encapsulating common block header/template type actions.
    """
    def __init__(self, raw=None, coin=None):
        # little endian bytes
        self.hashprev = None
        # ints
        self.ntime = None
        self.bits = None
        self.version = 2
        # assumes that the extranonce padding is missing
        self.coinbase1 = None
        self.coinbase2 = None
        # expects a list of Transaction objects...
        self.transactions = None
        self.job_id = None
        self.total_value = None
        self._stratum_string = None

        # lazy loaded...
        self._merklebranch = None
        self.coinbase = None

        self.coin = coin
        self._hash_func = get_hash_func(self.coin)

        # Darkcoin Masternode Voting
        self.vmn = []
        self.masternode_payments = False

        if coin == 'HVC':
            self.maxvote = 1024
        else:
            self.maxvote = 0 # MLS vote is allways 0
        self.reward = None # Heavycoin, Mozzshare

    @classmethod
    def from_gbt(cls, retval, coinbase, extra_length=0, transactions=None, coin=None):
        """ Creates a block template object from a get block template call
        and a coinbase transaction object. extra_length needs to be the length
        of padding that was added for extranonces (both 1 and 2 if added).
        Transactions should be a list of Transaction objects that will be
        put into the block. """
        if transactions is None:
            transactions = []
        coinbase1, coinbase2 = coinbase.assemble(split=True)
        inst = cls(coin=coin)
        inst.hashprev = unhexlify(reverse_hash(retval['previousblockhash']))
        inst.ntime = retval['curtime']
        inst.bits = unhexlify(retval['bits'])
        inst.version = retval['version']
        inst.total_value = retval.get('coinbasevalue')

        # Darkcoin
        inst.masternode_payments = retval.get('masternode_payments')
        for vote in retval.get('votes', []):
            v = CMasterNodeVote()
            v.deserialize(StringIO.StringIO(unhexlify(vote)))
            inst.vmn.append(v)

        inst.reward = retval.get('reward')
        if retval.has_key('maxvote'):
            inst.maxvote = retval.get('maxvote')

        # chop the padding off the coinbase1 for extranonces to be put
        if extra_length > 0:
            inst.coinbase1 = coinbase1[:-1 * extra_length]
        else:
            inst.coinbase1 = coinbase1
        inst.coinbase2 = coinbase2
        inst.transactions = transactions
        inst.coin = coin
        inst._hash_func = get_hash_func(coin)
        return inst

    # MERKLE_BRANCH
    # =================================================
    @property
    def merklebranch_be(self):
        """ Generate (or cache) merkle branch in be bytes """
        if self._merklebranch is None:
            self._merklebranch = merklebranch(self.transactions, be=True, hashes=False, hash_func=self._hash_func)
        return self._merklebranch

    @property
    def merklebranch_le(self):
        return [leaf[::-1] for leaf in self.merklebranch_be]

    @property
    def merklebranch_be_hex(self):
        return [hexlify(leaf) for leaf in self.merklebranch_be]

    @property
    def merklebranch_le_hex(self):
        return [hexlify(leaf[::-1]) for leaf in self.merklebranch_be]

    # HASH_PREV
    # =================================================
    @property
    def hashprev_le(self):
        return self.hashprev

    @property
    def hashprev_le_hex(self):
        return hexlify(self.hashprev)

    @property
    def hashprev_be_hex(self):
        return reverse_hash(hexlify(self.hashprev))

    # BITS
    # =================================================
    @property
    def bits_be_hex(self):
        return hexlify(self.bits)

    @property
    def bits_be(self):
        return self.bits

    @property
    def bits_target(self):
        return target_unpack(self.bits)

    # NTIME
    # =================================================
    @property
    def ntime_be_hex(self):
        return hexlify(pack(str(">I"), self.ntime))

    @property
    def ntime_be(self):
        return pack(str(">I"), self.ntime)

    @property
    def ntime_le(self):
        return pack(str("<I"), self.ntime)

    # VERSION
    # =================================================
    @property
    def version_be(self):
        return pack(str(">i"), self.version)

    @property
    def version_be_hex(self):
        return hexlify(pack(str(">i"), self.version))

    # MERKLEROOT
    # =================================================
    def merkleroot_be(self, coinbase):
        """ Accepts coinbase transaction object and returns what the merkleroot
        would be for this template """
        return from_merklebranch(self.merklebranch_le, coinbase, be=True, hash_func=self._hash_func)

    def merkleroot_le(self, coinbase):
        return self.merkleroot_be(coinbase)[::-1]

    def merkleroot_flipped(self, coinbase):
        """ Returns a byte string ready to be embedded in a block header """
        r = uint256_from_str(self.merkleroot_be(coinbase))
        rs = b""
        for i in xrange(8):
            rs += pack(str(">I"), r & 0xFFFFFFFFL)
            r >>= 32
        return rs[::-1]

    # HVC,MLS
    # =================================================
    @property
    def reward_be(self):
        return pack(str(">H"), self.reward)

    @property
    def reward_le(self):
        return pack(str("<H"), self.reward)

    @property
    def reward_be_hex(self):
        return hexlify(self.reward_be)

    @property
    def maxvote_be(self):
        return pack(str(">H"), self.maxvote)

    @property
    def maxvote_le(self):
        return pack(str("<H"), self.maxvote)

    @property
    def maxvote_be_hex(self):
        return hexlify(self.maxvote_be)

    @property
    def fee_total(self):
        return sum([t.fees or 0 for t in self.transactions])

    def block_header(self, nonce, extra1, extra2, ntime=None, nvote = None):
        """ Builds a block header given nonces and extranonces. Assumes extra1
        and extra2 are bytes of the proper length from when the coinbase
        fragments were originally generated (either manually, or using
        from_gbt)

        nonce: 4 bytes big endian hex
        extra1: direct from stratum, big endian
        extra2: direct from stratum, big endian
        ntime: 4 byte big endian hex
        """
        # calculate the merkle root by assembling the coinbase transaction

        coinbase_raw = self.coinbase1 + unhexlify(extra1) + unhexlify(extra2)
        coinbase_raw += self.coinbase2
        self.coinbase = Transaction(coinbase_raw, coin=self.coin)
        #coinbase.disassemble() for testing to ensure proper coinbase constr

        header = self.version_be
        header += self.hashprev_le
        header += self.merkleroot_flipped(self.coinbase)
        if ntime is None:
            header += self.ntime_be
        else:
            if isinstance(ntime, basestring):
                header += unhexlify(ntime)
            else:
                raise AttributeError("ntime must be hex string")
        header += self.bits_be
        header += unhexlify(nonce)

        if self.coin == 'HVC' or self.coin == 'MLS':
            header += self.reward_be
            if nvote is None:
                header += self.maxvote_be
            else:
                if isinstance(nvote, basestring):
                    header += unhexlify(nvote)
                else:
                    raise AttributeError("nvote must be hex string")
            return b''.join([header[i*4:i*4+4][::-1] for i in range(0, 21)])
        else:
            return b''.join([header[i*4:i*4+4][::-1] for i in range(0, 20)])

    def stratum_params(self):
        """ Generates a list of values to be passed to a work command for
        stratum minus the flush value """
        params = [self.job_id,
                self.hashprev_le_hex,
                hexlify(self.coinbase1),
                hexlify(self.coinbase2),
                self.merklebranch_le_hex,
                self.version_be_hex,
                self.bits_be_hex,
                self.ntime_be_hex,
                False, # clean_jobs default False
                ]
        if self.coin == 'HVC' or self.coin == 'MLS':
            params.append(self.reward_be_hex)
            params.append(self.maxvote_be_hex)
        return params

    def stratum_string(self):
        if not self._stratum_string:
            send_params = self.stratum_params() + ["REPLACE_ME"]
            send_params[0] = "%s"
            send = {'params': send_params, 'id': None, 'method': 'mining.notify'}
            base = json.dumps(send, separators=(',', ':')) + "\n"
            self._stratum_string = base.replace('"REPLACE_ME"', '%s')
        return self._stratum_string

    def submit_serial(self, header, raw_coinbase=None):
        """ assembles a block bytestring for submission. """
        block = header
        # encode number of transactions
        block += self.varlen_encode(len(self.transactions) + 1)
        # add the coinbase first
        if self.coinbase is None and not raw_coinbase:
            raise AttributeError("Coinbase hasn't been calculated")
        if raw_coinbase:
            block += raw_coinbase
        else:
            block += self.coinbase.raw
        # and all the transaction raw values
        for trans in self.transactions:
            block += trans.raw

        # Darkcoin
        if self.masternode_payments:
            block += ser_vector(self.vmn)

        return block
