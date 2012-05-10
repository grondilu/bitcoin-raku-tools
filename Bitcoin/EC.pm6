#!/usr/local/bin/perl6
# Ellicptic curve module
module Bitcoin::EC;
class Point {...}

constant $p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
constant $b = 0x0000000000000000000000000000000000000000000000000000000000000007;
constant $a = 0x0000000000000000000000000000000000000000000000000000000000000000;
our sub G returns Point {
    Point.new:
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    :order(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
}

package Modular {
    my Int $modulo = $p;
    our sub inverse(Int $n) returns Int {
	my Int ($c, $d, $uc, $vc, $ud, $vd) = ($n % $modulo, $modulo, 1, 0, 0, 1);
	my Int $q;
	while $c != 0 {
	    ($q, $c, $d) = ($d div $c, $d % $c, $c);
	    ($uc, $vc, $ud, $vd) = ($ud - $q*$uc, $vd - $q*$vc, $uc, $vc);
	}
	return $ud < 0 ?? $ud + $modulo !! $ud;
    }
}

multi prefix:<->(Point $a) { Point.new: $a.x, -$a.y % $p, :order($a.order) }
multi infix:<+>(Point $a, Point $b) { $a.clone.add($b) }
multi infix:<*>(Int $n, Point $a) { $a.clone.mult($n) }
multi infix:<*>(Point $a, Int $n) { $n * $a }

class Point {
    has Int $.x;
    has Int $.y;
    has Int $.order;
    method ^horizon { self.new: Int, Int };
    method is_at_horizon returns Bool { !defined($.x) or !defined($.y) }
    method new(Int $x, Int $y, Int :$order?) {
	my $new = self.Mu::new: :x($x), :y($y), :order($order);
	!!! "point is not on curve" unless $new.is_at_horizon or ($y**2 - ($x**3 + $a*$x + $b)) %% $p;
	return $new;
    }
    method gist { self.is_at_horizon ?? "point at horizon" !! "x: $.x, y: $.y" }
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
