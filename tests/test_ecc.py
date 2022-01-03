import pytest
import src.ecc as target


################################################################################
# FieldElement
################################################################################
@pytest.mark.parametrize('n1, p1, n2, p2', [
    (2, 7, 2, 7),
    (3, 11, 3, 11),
])
def test_fq_eq(n1, p1, n2, p2):
    assert target.FieldElement(n1, p1) == target.FieldElement(n2, p2)


@pytest.mark.parametrize('n1, p1, n2, p2', [
    (2, 7, 3, 7),
    (2, 7, 2, 5),
])
def test_fq_neq(n1, p1, n2, p2):
    assert target.FieldElement(n1, p1) != target.FieldElement(n2, p2)


@pytest.mark.parametrize('n1, n2, n3, p', [
    (2, 3, 5, 7),
    (5, 6, 4, 7),
])
def test_fq_add(n1, n2, n3, p):
    x1 = target.FieldElement(n1, p)
    x2 = target.FieldElement(n2, p)
    x3 = target.FieldElement(n3, p)
    assert x1 + x2 == x3


@pytest.mark.parametrize('n1, n2, n3, p', [
    (5, 3, 2, 7),
    (2, 5, 4, 7),
])
def test_fq_sub(n1, n2, n3, p):
    x1 = target.FieldElement(n1, p)
    x2 = target.FieldElement(n2, p)
    x3 = target.FieldElement(n3, p)
    assert x1 - x2 == x3


@pytest.mark.parametrize('n1, n2, n3, p', [
    (5, 3, 1, 7),
    (2, 5, 3, 7),
])
def test_fq_mul(n1, n2, n3, p):
    x1 = target.FieldElement(n1, p)
    x2 = target.FieldElement(n2, p)
    x3 = target.FieldElement(n3, p)
    assert x1 * x2 == x3


@pytest.mark.parametrize('n1, n2, n3, p', [
    (5, 6, 2, 7),
    (2, 3, 3, 7),
])
def test_fq_div(n1, n2, n3, p):
    x1 = target.FieldElement(n1, p)
    x2 = target.FieldElement(n2, p)
    x3 = target.FieldElement(n3, p)
    assert x1 / x2 == x3


@pytest.mark.parametrize('n1, e, n2, p', [
    (5, 1, 5, 7),
    (5, 2, 4, 7),
    (5, 3, 6, 7),
])
def test_fq_pow(n1, e, n2, p):
    x1 = target.FieldElement(n1, p)
    x2 = target.FieldElement(n2, p)
    assert x1**e == x2


################################################################################
# Point
################################################################################
def define_point(x, y, a, b, prime):
    p = target.Point(
        target.FieldElement(x, prime) if x is not None else None,
        target.FieldElement(y, prime) if y is not None else None,
        target.FieldElement(a, prime),
        target.FieldElement(b, prime),
    )
    return p


@pytest.mark.parametrize('x, y, a, b, prime', [
    (192, 105, 0, 7, 223),
    (17, 56, 0, 7, 223),
    (1, 193, 0, 7, 223),
])
def test_p_on_curve(x, y, a, b, prime):
    _ = define_point(x, y, a, b, prime)


@pytest.mark.parametrize('x, y, a, b, prime', [
    (200, 119, 0, 7, 223),
    (42, 99, 0, 7, 223),
])
def test_p_not_on_curve(x, y, a, b, prime):
    with pytest.raises(ValueError):
        _ = define_point(x, y, a, b, prime)


@pytest.mark.parametrize(
    'x1, y1, x2, y2, a, b, prime, x3, y3',
    [
        (170, 142, 60, 139, 0, 7, 223, 220, 181),
        (47, 71, 17, 56, 0, 7, 223, 215, 68),
        (143, 98, 76, 66, 0, 7, 223, 47, 71),
        (47, 71, 47, 71, 0, 7, 223, 36, 111),  # p + p = 2*p
        (223 - 1, 0, 223 - 1, 0, 0, 1, 223, None, None),  # p + p = 2*p = 0
        (47, 71, 47, 223 - 71, 0, 7, 223, None, None),  # p + (-p) = 0
    ])
def test_p_add(x1, y1, x2, y2, a, b, prime, x3, y3):
    p1 = define_point(x1, y1, a, b, prime)
    p2 = define_point(x2, y2, a, b, prime)
    p3 = define_point(x3, y3, a, b, prime)
    assert p1 + p2 == p3


@pytest.mark.parametrize(
    'x1, y1, x2, y2, a, b, prime, x3, y3',
    [
        (170, 142, None, None, 0, 7, 223, 170, 142),  # x + 0 = x
        (None, None, 170, 142, 0, 7, 223, 170, 142),  # 0 + x = x
        (None, None, None, None, 0, 7, 223, None, None),  # 0 + 0 = 0
    ])
def test_p_add_zero(x1, y1, x2, y2, a, b, prime, x3, y3):
    p1 = define_point(x1, y1, a, b, prime)
    p2 = define_point(x2, y2, a, b, prime)
    p3 = define_point(x3, y3, a, b, prime)
    assert p1 + p2 == p3


@pytest.mark.parametrize(
    'x1, y1, x2, y2, a, b, prime',
    [
        (47, 71, 47, 152, 0, 7, 223),  # inverse1
        (36, 111, 36, 112, 0, 7, 223),  # inverse2
    ])
def test_p_add_inverse(x1, y1, x2, y2, a, b, prime):
    p1 = define_point(x1, y1, a, b, prime)
    p2 = define_point(x2, y2, a, b, prime)
    zero = define_point(None, None, a, b, prime)
    assert p1 + p2 == zero


def test_p_add_associative():
    a, b, prime = 0, 7, 223
    p1 = define_point(170, 142, a, b, prime)
    p2 = define_point(60, 139, a, b, prime)
    p3 = define_point(143, 98, a, b, prime)
    assert (p1 + p2) + p3 == p1 + (p2 + p3)


@pytest.mark.parametrize(
    'x1, y1, x2, y2, a, b, prime',
    [
        (170, 142, 60, 139, 0, 7, 223),
        (47, 71, 17, 56, 0, 7, 223),
        (143, 98, 76, 66, 0, 7, 223),
        (47, 71, 47, 152, 0, 7, 223),  # inverse1
    ])
def test_p_add_commutative(x1, y1, x2, y2, a, b, prime):
    p1 = define_point(x1, y1, a, b, prime)
    p2 = define_point(x2, y2, a, b, prime)
    assert p1 + p2 == p2 + p1


@pytest.mark.parametrize('x1, y1, x2, y2, a, b, prime, r', [
    (47, 71, None, None, 0, 7, 223, 0),
    (47, 71, 47, 71, 0, 7, 223, 1),
    (47, 71, 36, 111, 0, 7, 223, 2),
    (47, 71, 15, 137, 0, 7, 223, 3),
])
def test_p_rmul(x1, y1, x2, y2, a, b, prime, r):
    p1 = define_point(x1, y1, a, b, prime)
    p2 = define_point(x2, y2, a, b, prime)
    assert r * p1 == p2


@pytest.mark.parametrize('x, y, a, b, prime, r1, r2', [
    (47, 71, 0, 7, 223, 2, 3),
    (47, 71, 0, 7, 223, 3, 220),
    (47, 71, 0, 7, 223, 1000, 2000),
])
def test_p_rmul_closure(x, y, a, b, prime, r1, r2):
    p = define_point(x, y, a, b, prime)
    assert r1 * p + r2 * p == (r1 + r2) * p


@pytest.mark.parametrize('x, y, a, b, prime, r1, r2', [
    (47, 71, 0, 7, 223, 0, 21),
    (47, 71, 0, 7, 223, 5, 16),
])
def test_p_rmul_inverse(x, y, a, b, prime, r1, r2):
    p = define_point(x, y, a, b, prime)
    zero = define_point(None, None, a, b, prime)
    assert r1 * p + r2 * p == zero
