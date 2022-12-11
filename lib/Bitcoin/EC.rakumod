#!/usr/local/bin/raku
unit module Bitcoin::EC;
=begin DESCRIPTION

In short, an elliptic curve is a set of integer coordinates of the plan,
satisfying an equation of the form:

    2   3
   y ≡ x  +  a x + b [modulo p]

The parameters a, b and p define the curve.  There are many different possible
curves, but bitcoin uses only one, named I<secp256k1>.  This module handles
only this particular curve.

Points of an elliptic curve have a group structure, which is used to define
exponentiation and thus DSA cryptography.  What is used is actually a cyclical 
subgroup, whose generator is also a parameter of the named curve.

According to Satoshi, the main advantage of ECDSA is that keys and signatures
are much shorter for the same cryptographic strength.

=end DESCRIPTION

constant p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
constant b = 7;
constant a = 0;

CHECK die "p needs to be prime" unless p.is-prime;

package Modular {
  our sub inverse(Int $n, Int $m = p) returns Int {
    if $m.is-prime { expmod $n, $m - 2, $m }
    else {
      my Int ($c, $d, $uc, $vc, $ud, $vd) = ($n % $m, $m, 1, 0, 0, 1);
      my Int $q;
      while $c != 0 {
	($q, $c, $d) = ($d div $c, $d % $c, $c);
	($uc, $vc, $ud, $vd) = ($ud - $q*$uc, $vd - $q*$vc, $uc, $vc);
      }
      return $ud < 0 ?? $ud + $m !! $ud;
    }
  }
}

our class Point {
    has Int ($.x, $.y, $.order);
    multi method new
    (
	Int:D $x,
	Int:D $y where ($y**2 - ($x**3 + a*$x + b)) %% p,
	Int :$order?
    ) { self.bless: :x($x % p), :y($y % p), :$order }
    multi method gist(::?CLASS:D:) { "EC Point at x=$.x, y=$.y" }
    multi method gist(::?CLASS:U:) { "point at horizon" }
    multi method Blob { blob8.new: ($!y %% 2 ?? 2 !! 3), $!x.polymod(256 xx 31).reverse }
    multi method Blob(:$uncompressed where ?*) {
      blob8.new: 0x04, ($!x, $!y).map: *.polymod(256 xx 31).reverse
    }
}

our constant G = Point.new:
0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
:order(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141);

multi sub infix:<eqv>(Point $a, Point $b) returns Bool is export { $a.x == $b.x && $a.y == $b.y }
multi sub prefix:<->(Point:U) { Point }
multi sub prefix:<->(Point:D $point) {
    Point.bless: :x($point.x), :y(-$point.y % p), :order($point.order);
}
multi infix:<->(Point $a, Point $b) { $a + -$b }

multi infix:<*>(Point $u, Int $n) is export { $n * $u }
multi infix:<*>(Int $n, Point:U) is export { Point }
multi infix:<*>(0, Point)          is export { Point }
multi infix:<*>(1, Point:D $point) is export { $point }
multi infix:<*>(2, Point:D $point) is export {
    my Int $l = (3*$point.x**2 + a) * Modular::inverse(2 *$point.y) % p;
    my Int $x = ($l**2 - 2*$point.x) % p;
    my Int $y = ($l*($point.x - $x) - $point.y) % p;
    if defined $point.order {
	Point.bless:
	:$x, :$y, :order($point.order %% 2 ?? $point.order div 2 !! $point.order);
    }
    else { Point.bless: :$x, :$y }
}

multi infix:<*>(Int $n where $n > 2, Point:D $point) is export {
  2 * ($n div 2 * $point) + $n % 2 * $point;
}

multi infix:<+>(Point:U, Point $b) { $b }
multi infix:<+>(Point:D $a, Point:U) { $a }
multi infix:<+>(Point:D $a, Point:D $b) {
    if ($a.x - $b.x) %% p {
	return ($a.y + $b.y) %% p ?? Point !! 2 * $a;
    }
    else {
	my $i = Modular::inverse($b.x - $a.x);
	my $l = ($b.y - $a.y) * $i % p;
	my $x = $l**2 - $a.x - $b.x;
	my $y = $l*($a.x - $x) - $a.y;
	return Point.bless: :x($x % p), :y($y % p);
    }
}

package DSA {
    role PublicKey {
	method verify(
	    Buf $h,
	    Int $r where 1..^p,
	    Int $s where 1..^p,
	) {
	    my $c = Modular::inverse $s, my $order = G.order;
	    my @u = map * *$c % $order, reduce(* *256 + *, $h.list), $r;
	    $_ =
		(reduce(* *256 + *, $h.list)*$c % $order) * G +
		($r*$c % $order) * self;
	    !!! 'wrong signature' unless .x % $order == $r; 
	}
    }
    class PrivateKey {
	our $order = G.order;
	has Int $.e;

	method new(Int $e) { self.bless: :e($e) } 
	method sign(Buf $h) {

	    # 1. Chose a random number k
	    my Int $k = reduce * *256+*, (^256).roll: ^32;

	    # 2. Compute k * G
	    my Point $point = $k * G;

	    # 3. Compute r s
	    my Int $r = $point.x % $order;
	    my Int $s =
	    Modular::inverse($k, $order) *
	    ($.e * $r + reduce * *256+*, $h.list) % $order
	    ;

	    # 4. Return r s
	    return $r, $s;
	}
	method public_key { $.e * G.clone but PublicKey }
    }
}

# vi: ft=raku
