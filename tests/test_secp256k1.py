import pytest
import src.secp256k1 as target


def test_constants():
    assert (target.N * target.G).x is None
    assert target.P % 4 == 3


def test_pubpoint():
    points = [
        (7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc,
         0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
        (1485,
         0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda,
         0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
        (2**128,
         0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da,
         0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
        (2**240 + 2**31,
         0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116,
         0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
    ]
    for s, x, y in points:
        assert s * target.G == target.S256Point(x, y)


def test_verify():
    point = target.S256Point(
        0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
        0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)

    zrs = [
        (
            0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60,
            0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395,
            0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4,
        ),
        (
            0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d,
            0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c,
            0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6,
        ),
    ]
    for z, r, s in zrs:
        assert point.verify(z, target.Signature(r, s))


def test_deterministic_k():
    pk = target.PrivateKey(1)
    assert pk.deterministic_k(10) == pk.deterministic_k(10)


@pytest.mark.parametrize('n', [1, 2, 4])
def test_s256field_sqrt(n):
    n = target.S256Field(n)
    sqrt = n.sqrt()
    assert n == sqrt**2


@pytest.mark.parametrize('p, compressed, expected_str', [
    ((999**3) * target.G, False,
     '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9'
     ),
    ((999**3) * target.G, True,
     '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'),
    ((2019**5) * target.G, True,
     '02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701'),
])
def test_s256point_sec(p, compressed, expected_str):
    expected = bytes.fromhex(expected_str)
    assert p.sec(compressed) == expected


@pytest.mark.parametrize('sec_bin_str, expected', [
    ('049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9',
     (999**3) * target.G),
    ('039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5',
     (999**3) * target.G),
    ('02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701',
     (2019**5) * target.G),
])
def test_s256point_parse(sec_bin_str, expected):
    sec_bin = bytes.fromhex(sec_bin_str)
    assert target.S256Point.parse(sec_bin) == expected


@pytest.mark.parametrize('p, compressed, testnet, expected', [
    ((888**3) * target.G, True, False, '148dY81A9BmdpMhvYEVznrM45kWN32vSCN'),
    ((888**3) * target.G, True, True, 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP'),
    (321 * target.G, False, False, '1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj'),
    (321 * target.G, False, True, 'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP'),
])
def test_s256point_address(p: target.S256Point, compressed: bool,
                           testnet: bool, expected: str):
    actual = p.address(compressed, testnet)
    assert actual == expected


@pytest.mark.parametrize('r, s, expected', [
    (1, 2, bytes.fromhex('30' + '06' + '020101' + '020102')),
    (0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6,
     0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec,
     bytes.fromhex(
         '3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec'
     ))
])
def test_signature_der(r, s, expected):
    sig = target.Signature(r, s)
    sig_der = sig.der()
    assert sig_der == expected
    sig_recover = target.Signature.parse(sig_der)
    assert sig_recover.r == r
    assert sig_recover.s == s


@pytest.mark.parametrize('s, compressed, testnet, expected', [
    (2**256 - 2**199, True, False,
     'L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC'),
    (2**256 - 2**201, False, True,
     '93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn'),
])
def test_privatekey_wif(s: int, compressed: bool, testnet: bool,
                        expected: str):
    pk = target.PrivateKey(s)
    assert pk.wif(compressed, testnet) == expected
