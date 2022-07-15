module Bitcoin::EC::BC;
=begin DESCRIPTION

This module provides elliptic curve arithmetics and cryptography using bc, the
Unix basic calculator.  It is much faster than a pure Perl6 implementation, so
we'll use this wrapper until Perl6 gets faster.

=end DESCRIPTION

our constant code = q[
/*
 *
 * A small library for elliptic curve arithmetics and cryptography with
 * bitcoin.
 *
 * 
 */

scale=0;

/* secp256k1 parameters */
ibase=16;
p= FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
b= 7;
a= 0;
gx=79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
gy=483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
go=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
ibase=A;

/* A modulo function that behaves well with negative numbers */
define true_mod(n, m) {
    if (n >= 0) return n%m else return -n*(m-1)%m;
}

/* modular inverse function */
define inverse_mod ( n, m ) {
    auto c, tc, d, td, uc, tuc, vc, tvc, ud, vd, q;
    c = true_mod(n, m); d = m; uc=1; vc=0; ud=0; vd=1; q=0;
    while (c != 0) {
	q = d / c;
	tc = c;
	c = true_mod(d, c);
	d = tc;

	tuc = uc;
	tvc = vc;
	uc = ud - q*uc;
	vc = vd - q*vc;
	ud = tuc;
	vd = tvc;
    }
    return true_mod(ud, m);
}

/* This test function should print a long sequence of '1'. */
define test_inverse_mod () {
    auto n, i;
    n = 2017;
    for (i=1; i<n; i++) print (i * inverse_mod(i, n)), n;
}

/* 
 * Elliptic curve operations.
 *
 * For simplicity, we\'ll ignore the possibiliy of a
 * point at horizon. 
 *
 * BC functions can not return multiple values,
 * so we'll use a base-p encoding for points.
 *
 */

define add( point_a, point_b ) {
    auto i, l, x, y, xa, ya, xb, yb;
    xa = point_a / p; ya = point_a % p;
    xb = point_b / p; yb = point_b % p;
    i = inverse_mod( xb - xa, p );
    l = true_mod((yb - ya) * i, p);
    x = l^2 - xa - xb;
    y = l*(xa - x) - ya;
    return true_mod(x, p) *p + true_mod(y, p);
}

define double( point ) {
    auto l, x, y, xout, yout;
    x = point / p; y = point % p;
    l = true_mod((3*x^2 + a) * inverse_mod( 2*y, p ), p);
    xout = true_mod(l^2 - 2*x, p);
    yout = true_mod(l*(x - xout) - y, p);
    return xout * p + yout;
}

define mult( k, point ) {
    if (k == 1) return point;
    if (k == 2) return double( point );
    if (k % 2 == 0) return double( mult( k/2, point ) );
    return add(point, double( mult( k/2, point ) ));
}

];

our sub compute(Str $expression) {
    return map {:16($_)},
    qqx[
    echo "{code}
    tmp = $expression;
    obase=16;
    tmp / p
    tmp % p
    quit" |
    bc -q
    ].comb: /<xdigit>+/;
}
