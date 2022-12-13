unit module Bitcoin::BIP32;
use Digest::HMAC:auth<grondilu>;
use Digest::SHA2;
use Digest::RIPEMD;

use Bitcoin::EC;

sub postfix:<h>(UInt $i) is export { $i + 2**31 }

sub ser32(uint32 $i --> blob8) { blob8.new: $i.polymod(256 xx 3).reverse; }
sub ser256(UInt  $p --> blob8) { blob8.new: $p.polymod(256 xx 31).reverse; }

sub parse256(blob8 $b --> UInt) { $b.list.reduce: 256 * * + * }

need Bitcoin::BIP32::ExtendedKey::Private;
need Bitcoin::BIP32::ExtendedKey::Public;
class MasterKey is Bitcoin::BIP32::ExtendedKey::Private is export {
  multi method new(Blob $seed) {
    my $sha512 = hmac
      key => "Bitcoin seed",
      msg => $seed,
      hash => &sha512, block-size => 128;
    my ($Il, $Ir) = map { $sha512.subbuf($_, 32) }, 0, 32;

    samewith
      depth        => 0,
      fingerprint  => 0,
      child-number => 0,
      chain-code   => $Ir,
      key          => $Il.list.reduce(256 * * + *)
    ;
  }
}

sub N(
  Bitcoin::BIP32::ExtendedKey::Private $key -->
  Bitcoin::BIP32::ExtendedKey::Public
) is export {
  Bitcoin::BIP32::ExtendedKey::Public.new:
    depth        => $key.depth,
    fingerprint  => $key.fingerprint,
    child-number => $key.child-number,
    chain-code   => $key.chain-code,
    point        => $key.Point
}

multi infix:</>(Bitcoin::BIP32::ExtendedKey::Private $k, UInt $i) is export {
  my ($left, $right) = .subbuf(0, 32), .subbuf(32) given 
    hmac
      key => $k.chain-code,
      msg => ($i ≥ 2**31 ?? $k.key !! $k.Point.Blob) ~ ser32($i),
      hash => &sha512, block-size => 128
  ;
  $k.new:
    depth          => $k.depth + 1,
    fingerprint    => $k.identifier.subbuf(0, 4).list.reduce(256 * * + *),
    child-number   => $i,
    chain-code     => $right,
    key            => parse256($left) + $k.Int
  ;
}

multi infix:</>(Bitcoin::BIP32::ExtendedKey::Public $K, UInt $i where * < 2**31) is export {

  my ($left, $right) = .subbuf(0, 32), .subbuf(32) given 
    hmac(key => $K.chain-code, msg => $K.key ~ ser32($i), hash => &sha512, block-size => 128);

  Bitcoin::BIP32::ExtendedKey::Public.new:
    depth          => $K.depth + 1,
    fingerprint    => $K.identifier.subbuf(0, 4).list.reduce(256 * * + *),
    child-number   => $i,
    chain-code     => $right,
    point => $left.list.reduce(256 * * + *)*Bitcoin::EC::G + $K.Point;
}
