unit module BIP32;
use Digest::HMAC:auth<grondilu>;
use Digest::SHA2;
use Digest::RIPEMD;

use secp256k1;

role xkey {

  method version returns uint32 {...}
  method key returns Blob {...}
  method Point returns Point {...}

  has uint8 $.depth;
  has uint32 ($.fingerprint, $.child-number);
  has blob8 $.chain-code;
  submethod TWEAK {
    die "wrong chain code length" unless $!chain-code.elems  == 32;
    die "wrong key length"        unless self.key.elems      == 33;
  }
  method Blob {
    blob8.new(
	self.version.polymod(256 xx 3).reverse,
	self.depth,
	self.fingerprint.polymod(256 xx 3).reverse,
	self.child-number.polymod(256 xx 3).reverse
	) ~ self.chain-code ~ self.key
  }

  {
    use Digest::SHA2;
    use Digest::RIPEMD;
    method Str {
      use Base58;
      Base58::encode self.Blob ~ (sha256 sha256 self.Blob).subbuf(0, 4);
    }
    method identifier returns Blob { rmd160 sha256 self.Point.Blob; }
  }

}


sub postfix:<h>(UInt $i) is export { $i + 2**31 }

sub ser32(uint32 $i --> blob8) { blob8.new: $i.polymod(256 xx 3).reverse; }
sub ser256(UInt  $p --> blob8) { blob8.new: $p.polymod(256 xx 31).reverse; }

sub parse256(blob8 $b --> UInt) { $b.list.reduce: 256 * * + * }

class xprv does xkey is export {

  {
    use secp256k1;
    submethod TWEAK { $!key %= G.order }
    method Point { self.Int*G }
  }

  has UInt $.key handles Int;

  method version { %*ENV<BITCOIN_TEST> ?? 0x04358394 !! 0x0488ADE4; }
  method key returns Blob { blob8.new: $!key.polymod(256 xx 32).reverse }

}

class xpub does xkey is export {

  use secp256k1;
  has Point $.Point;

  method version { %*ENV<BITCOIN_TEST> ?? 0x043587CF !! 0x0488B21E }
  method key { self.Point.Blob }

}

class MasterKey is xprv is export {
  multi method new { samewith blob8.new: ^258 .roll: 16 }
  multi method new(Blob $seed) {
    my $sha512 = hmac
      key => "Bitcoin seed",
      msg => $seed,
      hash => &sha512, block-size => 128;
    my ($Il, $Ir) = map { $sha512.subbuf($_, 32) }, 0, 32;

    self.bless:
      depth        => 0,
      fingerprint  => 0,
      child-number => 0,
      chain-code   => $Ir,
      key          => $Il.list.reduce(256 * * + *)
    ;
  }
}

sub N(xprv $xprv --> xpub) is export {
  xpub.new:
    depth        => $xprv.depth,
    fingerprint  => $xprv.fingerprint,
    child-number => $xprv.child-number,
    chain-code   => $xprv.chain-code,
    Point        => $xprv.Point
}

multi infix:</>(xprv $k, UInt $i) is export {
  my ($left, $right) = .subbuf(0, 32), .subbuf(32) given 
    hmac
      key => $k.chain-code,
      msg => ($i ≥ 2**31 ?? $k.key !! $k.Point.Blob) ~ ser32($i),
      hash => &sha512, block-size => 128
  ;
  xprv.new:
    depth          => $k.depth + 1,
    fingerprint    => $k.identifier.subbuf(0, 4).list.reduce(256 * * + *),
    child-number   => $i,
    chain-code     => $right,
    key            => parse256($left) + $k.Int
  ;
}

multi infix:</>(xpub $K, UInt $i where * < 2**31) is export {

  my ($left, $right) = .subbuf(0, 32), .subbuf(32) given 
    hmac(key => $K.chain-code, msg => $K.key ~ ser32($i), hash => &sha512, block-size => 128);

  xpub.new:
    depth          => $K.depth + 1,
    fingerprint    => $K.identifier.subbuf(0, 4).list.reduce(256 * * + *),
    child-number   => $i,
    chain-code     => $right,
    Point          => $left.list.reduce(256 * * + *)*G + $K.Point;
}
