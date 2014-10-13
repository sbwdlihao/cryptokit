from __future__ import unicode_literals
from future.builtins import bytes, range

import unittest

from cryptokit.base58 import get_bcaddress_version, get_bcaddress, b58encode, b58decode
from cryptokit.transaction import Input, Transaction, Output
from cryptokit.block import BlockTemplate, from_merklebranch, merklebranch, merkleroot
from cryptokit import target_unpack, target_from_diff, Hash, uint256_from_str, bits_to_difficulty, bits_to_shares, sha256d, hvc_hash, hvc_powhash
from cryptokit.bitcoin import data

from binascii import unhexlify, hexlify
from pprint import pprint
from struct import pack

class TestHashTuple(unittest.TestCase):
    def test_hash_hex(self):
        hsh = Hash.from_be_hex(
            "c8a78165527ab2022a57b095fef86c83e472b7d639cc246c3b40623c374fed4d")
        self.assertEquals(
            "d4def473c32604b3c642cc936d7b274e38c68fef590b75a2202ba72556187a8c",
            hsh.le_hex)
        self.assertEquals(
            "8c7a185625a72b20a2750b59ef8fc6384e277b6d93cc42c6b30426c373f4ded4",
            hsh.be_hex)

    def test_sha(self):
        a = Hash.from_be_hex("0549ac6ce7c0256174f29aec802d59ad5dcd49da0160f55b793bf056b0ab87d3")
        b = Hash.from_be_hex("e010c10d8b9a7ab835498f160ed1ab585d4a5d30f88d431988254ec9120371cf")
        sha = a.sha(b)
        print sha.be_hex


class TestMerkleRoot(unittest.TestCase):
    def test_from_merkle(self):
        hashes = [
            u'0549ac6ce7c0256174f29aec802d59ad5dcd49da0160f55b793bf056b0ab87d3',
            u'e010c10d8b9a7ab835498f160ed1ab585d4a5d30f88d431988254ec9120371cf',
            u'29057d0ebb70519850697a2004909ce7fe986162fb31dbd3817db378ab0f4dbb',
            u'b225985430eda525cfb40f0fc390ab6138b037b3418e1f32abb386e028352c65',
            u'20bae70c4a10dabd6a9c34a2a81f05bfeede917dcf0c9cacbb40278f3f8fb36a',
            ]
        deserial = [unhexlify(hsh)[::-1] for hsh in hashes]
        fake_coinbase = Transaction()
        fake_coinbase._hash = deserial[0]
        branch = merklebranch(deserial[1:], hashes=True)

        self.assertEquals(
            "652a365df3f5498cc5e9c578f20df9607a739c659711efa35cdc74f247410dc5",
            hexlify(merkleroot(deserial, hashes=True, be=True)[0]).decode('ascii'))

        self.assertEquals(
            "652a365df3f5498cc5e9c578f20df9607a739c659711efa35cdc74f247410dc5",
            hexlify(from_merklebranch(branch, fake_coinbase, True)))

    def test_from_merkle_hvc(self):
        hashes = [
            u'0511ad21ba69ece737568f72f925b068807aedb0f329aba76d8c9ccffd68add9',
            u'fbd125fba1d3dcd0852abfefbb21a78b0fbf3627ede4a0c7180f023564bc047c',
            u'57930b0987f5974b6637ba33eacf1a8c659ada1ef24a199003b39a2879ad2a13',
            u'56183660728d5890468f96b7e0c4c7b69ec370557375700cdd8ec2bbf4f774f7',
            ]
        deserial = [unhexlify(hsh)[::-1] for hsh in hashes]
        fake_coinbase = Transaction(coin='HVC')
        fake_coinbase._hash = deserial[0]
        branch = merklebranch(deserial[1:], hashes=True, hash_func=hvc_hash)

        self.assertEquals(
            "bf97c8ac14a0c115598e2d06f4522b332415a568a0f16330d8f8317534829160",
            hexlify(merkleroot(deserial, hashes=True, be=True, hash_func=hvc_hash)[0]).decode('ascii'))

        self.assertEquals(
            "bf97c8ac14a0c115598e2d06f4522b332415a568a0f16330d8f8317534829160",
            hexlify(from_merklebranch(branch, fake_coinbase, True, hash_func=hvc_hash)))

    def test_from_merkle_mls(self):
        hashes = [
            u'044af3d25dd487c982e85ff45c40d41561bcdc3477174862460db9583143beaa',
            u'4e6c02a0ab2ba51e9da9c10556b293a708884030b4145f5fa5357372c71a836f',
            ]
        deserial = [unhexlify(hsh)[::-1] for hsh in hashes]
        fake_coinbase = Transaction(coin='HVC')
        fake_coinbase._hash = deserial[0]
        branch = merklebranch(deserial[1:], hashes=True, hash_func=hvc_hash)

        self.assertEquals(
            "dcef589f3e0b3ce034709b16d59543aae3ea19897ccea87778072537aa7ce8a2",
            hexlify(merkleroot(deserial, hashes=True, be=True, hash_func=hvc_hash)[0]).decode('ascii'))

        self.assertEquals(
            "dcef589f3e0b3ce034709b16d59543aae3ea19897ccea87778072537aa7ce8a2",
            hexlify(from_merklebranch(branch, fake_coinbase, True, hash_func=hvc_hash)))


class TestBlockTemplate(unittest.TestCase):
    def test_block_header4(self):
        # pulled from mozzshare blockchain and modded slightly with full block header
        block_data = {
            'bits': '1b65bf06',
            'hash': '00000000005f53a4158ec81a7f936875b117add6ddf16052be69db814ed08e5d',
            'height': 95477,
            'merkleroot': '68214acafcc87de6c6bf0389cf6fbaf85ce602972e188a422320260f28e57adc',
            'nonce': hexlify(pack(str(">L"), 12348287)),
            'previousblockhash': '00000000003fbdcb0529f2df6b9e846092c25fd472117f2dade884be824a519f',
            'curtime': 1412981134,
            "reward": 120,
            'tx': [
                ('273de181f48d64299a81b16705fc0d7d9ee392e258af96a1e10a9dffce13d64c', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2703f57401062f503253482f048661385408f80031f9dc0100000d2f7374726174756d506f6f6c2f0000000001408544cb020000001976a9145944e74d6aaf83be927703ad95e7308787bb55c588ac00000000'),
                ('d4fb5de6290873a66171d167ae91cec59e116e23c2a88b50741671a76061176e', '0100000001fccce331a39a2b923ee88c7660e0803214f9a677314f21c7cb3a81e25eeb9158010000006c493046022100c13d4e43a267fa6e3b74d559eb985e886d8efe6d7f78c6105d5f6e46677e9c0d02210096e2acfc2e745286c0e948cd3f085a2da6d396277644669f448699a280bcc955012102dfaf5dfed2eec785ed262b574b2cf1c2b5e613ca5149b24725b54cb62c8e94acffffffff02f2f1b507000000001976a914ea76974eccf823d94a3615c1a0a117dec16533d888ac1ac96ae4010000001976a914e2c6ffbd9a5187e474d8278f4d2ad4f2adad17cf88ac00000000'),
                ('2daaa24179c2bf1c95da24f8ea3bf4d2722326c03f6407676b23edb42d0c908d', '010000000154f1cf0ee5b7efd7e3f3d3e1b81d98c743c0b1ab8257a82119ac6d0e73362876000000006b4830450220153fb11ac82d3d97addb82e717d5cc95c0d4c31dc709d4f634f82d5c93bb2730022100b12f8251a57238bbaa5c1e6c6552c1d64671a0130a24afcffad723b6fe0f8bfc0121024a192ab361b42cb0aab26e877423b4c51402d98423912f5faad243a301285e9dffffffff02ca154407000000001976a914b652ec06255ecd4708f416e8ae17646b773d09e088acef47e09c010000001976a9149212ca9f86bc8f699f31be024d092963661a0eff88ac00000000'),
            ],
            'version': 325781176}
        # make a list of objects
        # confirm that the objects hash correctly
        coinbase = None
        transactions = [Transaction(unhexlify(data.encode('ascii')), disassemble=True, coin='MLS')
                        for _, data in block_data['tx']]
        self.assertEquals(hexlify(merkleroot(transactions, be=True, hash_func=hvc_hash)[0]).decode('ascii'), block_data['merkleroot'])
        for obj, hsh in zip(transactions, block_data['tx']):
            hsh = hsh[0]
            obj.disassemble()
            self.assertEquals(obj.behexhash, hsh)
            if obj.is_coinbase:
                idx = transactions.index(obj)
                coinbase = transactions.pop(idx)
                print("Found coinbase idx {} Amount is {}"
                      .format(idx, coinbase.outputs[0].amount))

        pprint(coinbase.to_dict())
        tmplt = BlockTemplate.from_gbt(block_data, coinbase,
                                       transactions=transactions, coin='MLS')
        self.assertEquals(hexlify(tmplt.merkleroot_be(coinbase)).decode('ascii'),
                          block_data['merkleroot'])
        header = tmplt.block_header(block_data['nonce'], b'', b'')
        self.assertEquals(block_data['hash'], hexlify(hvc_powhash(header)[::-1]).decode('ascii'))

    def test_block_header3(self):
        # pulled from heavycoin blockchain and modded slightly with full block header
        block_data = {
            'bits': '1c040773',
            'hash': '000000000035ef615d0708b7409021bde4e29ab063f7f8b531197d8230a931ca',
            'height': 122588,
            'merkleroot': '105faebb2ac14858bbf92d1ebd29dd49b5fd532a54097bc76818e3668dd6925b',
            'nonce': hexlify(pack(str(">L"), 825226627)),
            'previousblockhash': '0000000003d8d235668c6d41389dd703b828f4a0f02d30a37e62ca10ab144b3f',
            'curtime': 1409012334,
            "vote" : 1,
            "reward" : 434,
            'tx': [
                ('105faebb2ac14858bbf92d1ebd29dd49b5fd532a54097bc76818e3668dd6925b', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1103dcde010453fbd26e7b00000b7b000000ffffffff010072d71a0a0000001976a914caf784fd449b3cdde48c7542640f14b34aed42fd88ac00000000')],
            'version': 350470948}
        # make a list of objects
        # confirm that the objects hash correctly
        coinbase = None
        transactions = [Transaction(unhexlify(data.encode('ascii')), disassemble=True, coin='HVC')
                        for _, data in block_data['tx']]
        self.assertEquals(hexlify(merkleroot(transactions, be=True, hash_func=hvc_hash)[0]).decode('ascii'), block_data['merkleroot'])
        for obj, hsh in zip(transactions, block_data['tx']):
            hsh = hsh[0]
            obj.disassemble()
            self.assertEquals(obj.behexhash, hsh)
            if obj.is_coinbase:
                idx = transactions.index(obj)
                coinbase = transactions.pop(idx)
                print("Found coinbase idx {} Amount is {}"
                      .format(idx, coinbase.outputs[0].amount))

        pprint(coinbase.to_dict())
        tmplt = BlockTemplate.from_gbt(block_data, coinbase,
                                       transactions=transactions, coin='HVC')
        self.assertEquals(hexlify(tmplt.merkleroot_be(coinbase)).decode('ascii'),
                          block_data['merkleroot'])
        header = tmplt.block_header(block_data['nonce'], b'', b'', nvote=hexlify(pack(str(">H"), block_data['vote'])))
        self.assertEquals(block_data['hash'], hexlify(hvc_powhash(header)[::-1]).decode('ascii'))

    def test_block_header2(self):
        # pulled from litecoin blockchain and modded slightly with full block header
        block_data = {
            'bits': '1d018ea7',
            'hash': 'adf6e2e56df692822f5e064a8b6404a05d67cccd64bc90f57f65b46805e9a54b',
            'height': 29255,
            'merkleroot': '066b2a758399d5f19b5c6073d09b500d925982adc4b3edd352efe14667a8ca9f',
            'nonce': hexlify(pack(str(">L"), 3562614017)),
            'previousblockhash': '279f6330ccbbb9103b9e3a5350765052081ddbae898f1ef6b8c64f3bcef715f6',
            'curtime': 1320884152,
            'tx': [
                ('066b2a758399d5f19b5c6073d09b500d925982adc4b3edd352efe14667a8ca9f', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804b217bb4e022309ffffffff0100f2052a010000004341044870341873accab7600d65e204bb4ae47c43d20c562ebfbf70cbcb188da98dec8b5ccf0526c8e4d954c6b47b898cc30adf1ff77c2e518ddc9785b87ccb90b8cdac00000000')],
            'version': 1}
        # make a list of objects
        # confirm that the objects hash correctly
        coinbase = None
        transactions = [Transaction(unhexlify(data.encode('ascii')), disassemble=True)
                        for _, data in block_data['tx']]
        self.assertEquals(hexlify(merkleroot(transactions, be=True)[0]).decode('ascii'), block_data['merkleroot'])
        for obj, hsh in zip(transactions, block_data['tx']):
            hsh = hsh[0]
            obj.disassemble()
            self.assertEquals(obj.behexhash, hsh)
            if obj.is_coinbase:
                idx = transactions.index(obj)
                coinbase = transactions.pop(idx)
                print("Found coinbase idx {} Amount is {}"
                      .format(idx, coinbase.outputs[0].amount))

        pprint(coinbase.to_dict())
        tmplt = BlockTemplate.from_gbt(block_data, coinbase,
                                       transactions=transactions)
        self.assertEquals(hexlify(tmplt.merkleroot_be(coinbase)).decode('ascii'),
                          block_data['merkleroot'])
        header = tmplt.block_header(block_data['nonce'], b'', b'')
        self.assertEquals(block_data['hash'], hexlify(sha256d(header)[::-1]).decode('ascii'))

    def test_block_header(self):
        # pulled from dogecoin blockchain and modded slightly, height 50000
        block_data = {
            'bits': '1c00c7ec',
            'hash': 'e4cab588a33147a217c8bc2f923fcd1f642fde26c7c797a5c2c4808c4c617a7e',
            'height': 50000,
            'merkleroot': '5af19843e6220965f3c4b5f8d3995796edff0aad5ee4cc6ab849333881c001e1',
            'nonce': hexlify(pack(str(">L"), 3014526208)),
            'previousblockhash': '7f0502292609f5949260403176e8874ec7c5376397641d3f660648e7fdda0bab',
            'curtime': 1389349309,
            'tx': [
                ('d4eeb0cd44a4339d1a9fe8cea9482689165cff6ed1a3f4815bafcb443cdd271e', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff250350c300062f503253482f04bcc9cf5208f80032c0020000000b2f4e757432506f6f6c732f00000000010b54074f2f4b00001976a9141b3fdba0ff497a9d8e84d65e9b078e23e46e97f088ac00000000'),
                ('481fce0e2572dd782369dcc2457c267bb70918e825dfedd6e178ddf28d016cde', '0100000006ca0667d0021af9199f134a38ece3f813200f457282c2904d11b5c14a773ad514010000006b48304502200470b7b254b1d4b75f3318c6348ac97e2ba35f4be838aa10b50429107b4a8026022100864687886781c4a16de03b18fc5236bd379a6655f075b75da308b9bc3d7565b801210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff9f9316e06ba91ceb8d93a3f3b1286570ccc9f5720c944a556e37a11a0789d99a010000006b483045022100fc72dadfb07f7253b948bd94c3e9e534a4f45fdd70d6f25e865afc079f5f07ac022028be9ec4d68e700f5843a72e387f1a2bdf0cacb06f19ad8fbbc3db15ceaadd9401210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffffcc803949dfe10ac0d9b7adc4b560a52fdbfc3fbf5a2cd4c515bdc1ccee1919e6010000006a4730440220385fb14c3f6559557c6ff0a1beab9c0a3a1f3ee7b5c466874566f25063be13fb022001b84680899638bd99fcea1f8a007ccda4df954a594210a1e6b2644c681b56b601210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff340b8f285ceea5a123aaae8d33fd940442962894b8276a0f1d0959072c85b1e2010000006b4830450221008c592892fb530499f75065d4c741a97bb89e7aab7f156cf6471e134e41d19b3802202355e2f57c8ab27eb9445612e18f8ca0c51d0c8bad035082f784157db006419501210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff57835281cd613c9afc81e339d4d6b5ff20e25b381015b99ad863c3cec9c456d3010000006b48304502201ebdf69c6e146dc9f832d32439a1fef26011eecac1ffdc246ed37b726ca33f9a022100bb4e8f82c2c89c254700196f08e277af6964a04122a6395d42e61ffdbbb08ac601210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff5d22d9f2819f918f92bfb529c58201ed382a38d67a20c4277d104ecd92cb84c1010000006c493046022100834cfab229487cef0fe22dd07bbcf83bd3ce2696aee904b906c0cd8791e86a74022100a9dc16328ca8c648a0999d584fb1003fd4375aabe05d273143e976a735cf72f001210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff010011133a4f0200001976a914db4d7ba9e58109182b04307cd587fc0c79f659e788ac00000000'),
                ('74c60a18fc9a265cf78973d36e20b781ae427d4d62e9818bc51de000ef6fb1e3', '0100000006ec24cf82341457fe1f4e5a8aa70cd0cd24577d55de00f0220687edb5c4b18f48000000006b483045022100ca65846ad4fddc08b6e36853f6d0175df6a967c0c76c2804f07e3efe4a07901002207b67d8a7ee76dcf45f9515589381cccd2db33cb602b85f3f1abc873bfd2bb0680121037c533b95e310e28de6ea11179dac58b5a44e6de5eb37aacdfcb33c7d3c241cdaffffffffdf50b75ca17711f4e7060684389eaba1f9b928e160021ceb5348d338ecc827fa010000006a47304402202eca6850b9c25e8974441dd386b58d9a615ab8527f46890d10861916ee25b87f02201d35044b1ec20d6d2ec2e292354acc5d65ae8be10bf57cbd17d51ce0ac07dd6c012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150fffffffff6157a915b05f2c5d823123fb4b230b045fdbff0f68578d44de49f78cf0ede5b010000006b48304502201b61e8486f039524fb5a2fd51fdc75c170502a4adc43fdfefb830abcf572b4d0022100b5f134301962e661e8251f79182344d879dbd990c0513b6ee96ad45ffb5b9475012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffffd48aed18cad37e0d0f5bbcdd1b7f0a56899bdae664164dab0e243be02761a9ba010000006b483045022100c0c06d4fb2ec9f473f3b5fe9e96ab1379f9431cc639256a780d395b8c816a801022049c38e24224e02c7d103dbb4ffe650f86a85efbbd06e09f14bb68289813a88ce012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffffbb1f79fb8ef08188bbe5720afc51e8d4b17b227ac0575e06b113e9aa2cf73c9a010000006b483045022100de8dfc418ca7e9cbc3b8cee601e06ded8519490c3e3a69ad445e4bdbae6646a50220675e874008150d6c407211588819d42640e873cd5124a6acedfc66c7f5aae088012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffffdc2dff24673739435ef472cedc633557f21c6909822a40136c4b75c08797f6f7010000006a473044022045c537da10375757cb53ec70c06c6f00011c0759bdf8e6df2a012ce33153c7e102206e1e35d6f57c7de5ad37272efdecaf7313ada0e8f66f9532dd0747b09cb8003e012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffff0231cc5893000000001976a914262fee33cefdf111c3515c0502ba69073609904888ac0038c566e40200001976a914bd007a5819157bc912364e54fe7e0551df06d54888ac00000000'),
                ('12127842a829a588be0ac25a3ab5505925e79440d6911d22dd1059c79b9966e7', '0100000002ac367cb4c2ebd51066b0a87bac57a0f4876a6be781b1d2935bb49d1320c735f7000000006b48304502207a58e61dbe5ab39e7f6b3a91bf62a33102dfc6e7d2270d0f2cd31d0fd2b58a4a022100f27ffec655cf27ce9d4facbc9ce1b079f0c7b3fe80db69111695825e23628209012102c9619b298f6272cd0710ff5997f38dfd39096e3c95b92f857da6f4843e4afbc7ffffffff6c7fc27f6debb16714276edf12868ab5deab5a0cd64c5152928a2f3798e1ee01000000006c493046022100895790720f307d12a41a6df11c83fe2c991a857e63048e74dde91fb672a368ea022100bf9dac5625b454ee38dba9fc7e8e911bf5dc8cf504709413a9b12adb9b77bc26012103dedeabe4b6166d97479db844ca2defbbb8c5394b7576aafd6be67175062dc4beffffffff01008fd3ac8b0000001976a91464e5cfa48bf5f22ce5a5e739667ef61afb0b192d88ac00000000'),
                ('48d5713b929e28f1810cc7effdbfb0cb11bc88068bfbb1c9f076536b794715af', '010000000501049ee2eba48bf43470d5a6c1328fc29e3f434cae2f92d6b55bc6b694083d4f010000006a4730440220656c1c8c96ac2e72451e1ac69e496ee3768cd35741a4605579a770bde17ebe8e02207b0093e79f4f9e99795575699fd38496b2b12ce1b994054505c52dc9092a2bba01210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff17765b1d45fc0f0b0d9e060291bfaf19b9a219f3a74fb1fb6e20fda3278f252f010000006b4830450220264601cb87ca3579f4653248dfb539bd13bea41c63d378ab7ec86f5476ea99ab022100e5921d7d5b7c5421cf17a46729d1e08b26cfe3d64120d46a4c0faa623f91791301210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff94a09224a810a12eb793cb87802f58e31e5fc1f38831be221a4d2f9910893dcb010000006c4930460221008160791119449e306c9db0b3f22dde248bbc73babd732052b26a58b29c86287b022100ccdd9cb9eb9d8791c45b691d09f5aba2bfd69f279edd9c8177942748a5075ed901210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff9c9431729394c53656a625755dd2ff124a0d615932a2ea6befafd36812301ae0010000006a47304402202930eda28e865b8d190a305611473760df2b151175bc834155bc58435e82955102206eb77aceae4149715002ea4fee6eb2ffd807c1dc3fd37ea1d7eb28e88733883401210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffffae32166a760609d5fae1361f568977fb23e108a480a328298f075603a2bd124d010000006b48304502210094586a38aaa22ac5f1cb85871236057ae2fb8412fe5128768f2435eeadff0d8402202bd0000b2ddad2f1da83cfec60513aea0724f477bb55d5150e0de31955710c0d01210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff0100bccfcd5a0000001976a91442f319a15fd608b67ddddcc2e3badf1b90554fe088ac00000000'),
                ('212499f6527467b49cdf946524b42266ca8751616a41b7181d3a8931da7b240e', '01000000018fa554391f4e45ae96b9c6e9bd35f1cf38737ee9ad67ba401329df7497625513000000006b483045022019331f164d059057e5dc12bab158678ba65faf1b9542811434ce13e1179550b4022100e2375b7f350b18c1bde49c8ddd7d245282b931e1a8204018bb01b8abff94f4790121038f63d5c111706674f50f3d28729fe9848e9a3aee0b965c674d14e2155c5ee35bffffffff0200a3af46bb0000001976a9149cc45c2d78927f22ab4008a907becf6ab642258288aca019f807000000001976a9144d4952746b2777f3d07a89ad0ffd02e2e1d9aed288ac00000000'),
                ('47bce257235ab0f6c8526a12fc23e3bec10bbd1d87a3a261f624ff5c0d2730f2', '0100000001a16eaa30e2d56f3a3a94bf4b640c2ffaa3ccd09ce3926567b2e63e3f4d55df26000000006b48304502203579c6afe9b7365252c0424aa5e3b9d00c850f2beee0c0b2f66ac7652c4eb002022100ca44a4a0e7d2ff81de117efd144a89c70acc87eaf2e3454fed175f0ef9b6f562012103f5f17ee5b476803cf332d56c293ce59aa77a5046a284c9f7a523fefd911e9980ffffffff0260119d0a010000001976a9149e027ca13765f6558fcbab6acec2fc561fc5dd3288ac9ec1764b010000001976a914957acdecb251260da54dc8510497cb761db0698c88ac00000000'),
                ('6b74e1534ee50fc7158593831e322717fa536d65cbeb03fe53b30b31853fa033', '010000000153323c2dbba06bc58227354b013d31ba01ba814fa5681fb211c039979cac1643000000006b483045022054f7930a06af7da2a3e35c3fbb9bb0fbf5897c9296286de46d96763ea8c1d8fc0221009b8d53d5964a57fc8469ece1b0ef6f43e2cdbe1d4d72308d04491cb4705f95ce012103bbd11e6843ebcbcd2024265332738d8e1ebc7d0bb4b3a2e5b7a8bd6ece14bcb7ffffffff029feec0e4000000001976a91481d7f7a63b4a4e236b3b5d43067212e52bcd25ae88acf73d7520000000001976a91447cd32e2669d30d86d1c6708b890b9d7c7b632f188ac00000000')],
            'version': 1}
        # make a list of objects
        # confirm that the objects hash correctly
        coinbase = None
        transactions = [Transaction(unhexlify(data.encode('ascii')), disassemble=True)
                        for _, data in block_data['tx']]
        self.assertEquals(hexlify(merkleroot(transactions, be=True)[0]).decode('ascii'), block_data['merkleroot'])
        for obj, hsh in zip(transactions, block_data['tx']):
            hsh = hsh[0]
            obj.disassemble()
            self.assertEquals(obj.behexhash, hsh)
            if obj.is_coinbase:
                idx = transactions.index(obj)
                coinbase = transactions.pop(idx)
                print("Found coinbase idx {} Amount is {}"
                      .format(idx, coinbase.outputs[0].amount))

        tmplt = BlockTemplate.from_gbt(block_data, coinbase,
                                       transactions=transactions)
        self.assertEquals(hexlify(tmplt.merkleroot_be(coinbase)).decode('ascii'),
                          block_data['merkleroot'])
        header = tmplt.block_header(block_data['nonce'], b'', b'')
        self.assertEquals(block_data['hash'], hexlify(sha256d(header)[::-1]).decode('ascii'))

    def test_stratum_confirm(self):
        """ Test some raw data from cgminer submitting a share, confirm
        hashes come out the same as cgminer.
        Raw stratum params:
        """
        gbt = {u'bits': u'1e00e92b',
               u'coinbaseaux': {u'flags': u'062f503253482f'},
               u'coinbasevalue': 5000000000,
               u'curtime': 1392509565,
               u'height': 203588,
               u'mintime': 1392508633,
               u'mutable': [u'time', u'transactions', u'prevblock'],
               u'noncerange': u'00000000ffffffff',
               u'previousblockhash': u'b0f5ecb62774f2f07fdc0f72fa0585ae3e8ca78ad8692209a355d12bc690fb73',
               u'sigoplimit': 20000,
               u'sizelimit': 1000000,
               u'target': u'000000e92b000000000000000000000000000000000000000000000000000000',
               u'transactions': [],
               u'version': 2}

        extra1 = '0000000000000000'
        submit = {'extra2': '00000000', 'nonce': 'd5160000',
                  'result': '000050ccfe8a3efe93b2ee33d2aecf4a60c809995c7dd19368a7d00c86880f30'}

        # build a block template object from the raw data
        coinbase = Transaction()
        coinbase.version = 2
        coinbase.inputs.append(Input.coinbase(gbt['height'], [b'\0' * 12]))
        coinbase.outputs.append(Output.to_address(gbt['coinbasevalue'], 'D7QJyeBNuwEqxsyVCLJi3pHs64uPdMDuBa'))

        transactions = []
        for trans in gbt['transactions']:
            new_trans = Transaction(unhexlify(trans['data']), fees=trans['fee'])
            assert trans['hash'] == new_trans.lehexhash
            transactions.append(new_trans)
        bt = BlockTemplate.from_gbt(gbt, coinbase, 12, transactions)
        send_params = bt.stratum_params()
        print("job_id: {0}\nprevhash: {1}\ncoinbase1: {2}\ncoinbase2: {3}"
              "\nmerkle_branch: {4}\nversion: {5}\nnbits: {6}\nntime: {7}"
              .format(*send_params))

        header = bt.block_header(submit['nonce'], extra1, submit['extra2'])
        target = target_from_diff(1, 0x0000FFFF00000000000000000000000000000000000000000000000000000000)
        self.assertEquals(hexlify(sha256d(header)[::-1]).decode('ascii'), submit['result'])
        assert hash_int < target


class TestInput(unittest.TestCase):
    def test_coinbase_numeric(self):
        inp = Input.coinbase(120000)
        assert int.from_bytes(inp.script_sig[1:], byteorder='little') == 120000
        assert int.from_bytes(inp.script_sig[:1], byteorder='little') == 3


class TestUtil(unittest.TestCase):
    def test_target_unpack(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(
            target_unpack(b"\x1d\x00\xff\xff"),
            0x00000000FFFF0000000000000000000000000000000000000000000000000000)

    def test_bits_to_diff(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(bits_to_difficulty("1d00ffff"), 1)
        self.assertEquals(int(bits_to_difficulty("1b3be743")), 1094)

    def test_bits_to_shares(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(bits_to_shares("1b368901"), 1)

    def test_target_from_diff(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(
            target_from_diff(1),
            0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    def testb58(self):
        assert get_bcaddress_version('15VjRaDX9zpbA8LVnbrCAFzrVzN7ixHNsC') is 0
        _ohai = 'o hai'.encode('ascii')
        _tmp = b58encode(_ohai)
        assert _tmp == 'DYB3oMS'
        assert b58decode(_tmp, 5) == _ohai

    def test_address(self):
        # HVC test net
        self.assertIsNotNone(get_bcaddress_version('mp4hfsv6ESdc3jttjosmVBLdnnhL5wyKJm'))
        self.assertIsNotNone(get_bcaddress('mp4hfsv6ESdc3jttjosmVBLdnnhL5wyKJm'))
        # HVC main net
        self.assertIsNotNone(get_bcaddress_version('HR2KQ3qRWJ3yQhdivJLVVEScUg1EMp6EZH'))
        self.assertIsNotNone(get_bcaddress('HR2KQ3qRWJ3yQhdivJLVVEScUg1EMp6EZH'))
        # BTC,LTC... test net
        self.assertIsNotNone(get_bcaddress_version('nrJQ8mHB2AndBZiGT5m7ow7DgJeweCxT5n'))
        self.assertIsNotNone(get_bcaddress('nrJQ8mHB2AndBZiGT5m7ow7DgJeweCxT5n'))
        # BTC,LTC... test net
        self.assertIsNotNone(get_bcaddress_version('DGyiBd4UtcYB69dW1hL5TrySMUyPg1KSkg'))
        self.assertIsNotNone(get_bcaddress('DGyiBd4UtcYB69dW1hL5TrySMUyPg1KSkg'))


class TransactionTests(unittest.TestCase):
    def test_coinbase(self):
        coinbase = Transaction()
        coinbase.version = 2
        coinbase.inputs.append(Input.coinbase(12000, b'\0' * 6))
        coinbase.outputs.append(
            Output.to_address(50000, 'D7QJyeBNuwEqxsyVCLJi3pHs64uPdMDuBa'))
        one, two = coinbase.assemble(split=True)
        one = one[:-6]

        test = Transaction(one + unhexlify('0abcdef01012') + two)
        test.disassemble()
