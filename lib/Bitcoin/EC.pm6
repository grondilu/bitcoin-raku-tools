#!/usr/local/bin/perl6
module Bitcoin::EC;
class Point {...}

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
sub-group, whose generator is also a parameter of the named curve.

According to Satoshi, the main advantage of ECDSA is that keys and signatures
are much shorter for the same cryptographic strength.

=end DESCRIPTION


constant $p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
constant $b = 7;
constant $a = 0;
our sub G returns Point {
    Point.new:
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    :order(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
}

multi prefix:<->(Point $u) { Point.new: $u.x, -$u.y % $p, :order($u.order) }
multi infix:<*>(Point $u, Int $n) { $n * $u }

package Modular {
    our sub inverse(Int $n, Int $m = $p) returns Int {
	my Int ($c, $d, $uc, $vc, $ud, $vd) = ($n % $m, $m, 1, 0, 0, 1);
	my Int $q;
	while $c != 0 {
	    ($q, $c, $d) = ($d div $c, $d % $c, $c);
	    ($uc, $vc, $ud, $vd) = ($ud - $q*$uc, $vd - $q*$vc, $uc, $vc);
	}
	return $ud < 0 ?? $ud + $m !! $ud;
    }
}

class Point {
    has Int $.x;
    has Int $.y;
    has Int $.order;
    method ^horizon { self.new: Int, Int };
    method is_at_horizon returns Bool { !defined($.x) or !defined($.y) }
    method new(Int $x, Int $y, Int :$order?) {
	my $new = self.bless: *, :x($x), :y($y), :order($order);
	!!! "point is not on curve" unless $new.is_at_horizon or ($y**2 - ($x**3 + $a*$x + $b)) %% $p;
	return $new;
    }
    method gist { self.is_at_horizon ?? "point at horizon" !! "EC Point at x=$.x, y=$.y" }
    method double returns Point {
	return self.clone if self.is_at_horizon;
	my $l = (3*$.x**2 + $a) * Modular::inverse(2 *$.y) % $p;
	my $x = $l**2 - 2*$.x;
	($!x, $!y) = map { $_ % $p }, $x, $l*($.x - $x) - $.y;
	$!order div= 2 if defined $.order and $.order %% 2;
	return self;
    }
    method add(Point $point) returns Point {
	if self.is_at_horizon { return $point }
	elsif ($.x - $point.x) %% $p {
	    if ($.y + $point.y) %% $p { $!x = Int }
	    else { self.double }
	}
	else {
	    my $i = Modular::inverse($point.x - $.x);
	    my $l = ($point.y - $.y) * $i % $p;
	    my $x = $l**2 - $.x - $point.x;
	    ($!x, $!y) = map * % $p, $x, $l*($.x - $x) - $.y;
	    $!order = Int;
	}
	return self;
    }
    multi method mult(0) { $!x = $!y = $!order = Int; return self }
    multi method mult(Int $n is copy where $n > 0) {
	$n %= $.order if defined $.order;
	return Point.^horizon if self.is_at_horizon;
	my $n3 = 3 * $n;
	my $i = 1; $i *= 2 while $i <= $n3; $i div= 2;
	$_ = self.clone;
	while ( $i div= 2 ) > 1 {
	    .double;
	    .add( self)	if ($n3 +& $i) != 0 and ($n +& $i) == 0;
	    .add(-self)	if ($n3 +& $i) == 0 and ($n +& $i) != 0;
	}
	($!x, $!y, $!order) = (.x, .y, Int);
	return self;
    }

}

package DSA {
    class PublicKey {
	has Point $.point;
	method verify(
	    Buf $h,
	    Int $r where { 0 < $_ < $p },
	    Int $s where { 0 < $_ < $p }
	) {
	    my $c = Modular::inverse $s, my $order = G.order;
	    !!! "unexpected product" unless $c * $s % $order == 1;
	    my @u = map * *$c % $order, reduce(* *256 + *, $h.list), $r;
	    $_ =
		G.mult(reduce(* *256 + *, $h.list)*$c % $order).add:
		$.point.clone.mult: $r*$c % $order;
	    !!! 'wrong signature' unless .x % $order == $r; 
	}
    }
    class PrivateKey {
	has Int $.e;
	method new(Int $e) { self.bless: *, :e($e) } 
	method sign(Buf $h) {
	    ENTER { $*ERR.print: 'ECDSA signature is going to take some time. Please be patient... ' }
	    LEAVE { $*ERR.say:   'ok, done.' }

	    # 0. Store the group order
	    my $order = G.order;

	    # 1. Chose a random modular number k
	    my Int $k = reduce * *256+*, map { (^256).pick }, ^32;

	    # 2. Compute k * G
	    my Point $point = G.mult: $k;

	    # 3. Compute r s
	    my Int $r = $point.x % $order;
	    my Int $s =
	    Modular::inverse($k, $order) *
	    ($.e * $r + reduce * *256+*, $h.list) % $order
	    ;

	    # 4. Return r s
	    return $r, $s;
	}
	method public_key { PublicKey.new: :point(G.mult: $.e) }
    }

}

sub infix:<+>(PrivateKey $a, PrivateKey $b) {
    PrivateKey.new: $a.e + $b.e;
}
