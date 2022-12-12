unit module Bitcoin::BIP32;
use Digest::HMAC:auth("Lucien Grondin");
use Digest::SHA2;
use Digest::RIPEMD;

our constant %version-prefixes =
  mainnet => %(public => 0x0488B21E, private => 0x0488ADE4),
  testnet => %(public => 0x043587CF, private => 0x04358394)
  ;

sub postfix:<h>(UInt $i) is export { $i + 2**31 }

sub ser32(uint32 $i --> blob8) { blob8.new: $i.polymod(256 xx 3).reverse; }
sub ser256(UInt  $p --> blob8) { blob8.new: $p.polymod(256 xx 31).reverse; }

sub parse256(blob8 $b --> UInt) { $b.list.reduce: 256 * * + * }

role ExtendedKey {
  method version returns uint32 {...}
  has uint8 $.depth;
  has uint32 ($.fingerprint, $.child-number);
  has blob8 ($.chain-code, $.key);
  submethod TWEAK {
    die "wrong chain code length" unless $!chain-code == 32;
    die "wrong key"               unless $!key        == 33;
  }
  method Blob {
    blob8.new(
      self.version.polymod(256 xx 3).reverse,
      self.depth,
      self.fingerprint.polymod(256 xx 3).reverse,
      self.child-number.polymod(256 xx 3).reverse
    ) ~ self.chain-code ~ self.key
  }
  method Str {
    use Base58;
    given self.Blob {
      return Base58::encode $_ ~ (sha256 sha256 $_).subbuf(0, 4);
    }
  }
}

class PublicExtendedKey does ExtendedKey {
  method version { %version-prefixes{%*ENV<BITCOIN_TEST> ?? "testnet" !! "mainnet"}<public> }
}

class PrivateExtendedKey does ExtendedKey {
  method version { %version-prefixes{%*ENV<BITCOIN_TEST> ?? "testnet" !! "mainnet"}<private> }
  method Point {
    use Bitcoin::EC;
    Bitcoin::EC::G*self.key.list.reduce: 256* * + *
  }
  method publicKey {
    PublicExtendedKey.new:
      depth => self.depth,
      fingerprint => self.fingerprint,
      child-number => self.child-number,
      chain-code => self.chain-code,
      key => blob8.new: self.Point.Blob.list
  }
  method Int { parse256 self.key }
}

sub N(PrivateExtendedKey $key --> PublicExtendedKey) is export { $key.publicKey }

class MasterKey is PrivateExtendedKey is export {
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
      chain-code   => blob8.new(@$Ir),
      key          => blob8.new(0, |@$Il)
    ;
  }
}

multi infix:</>(PrivateExtendedKey $k, UInt $i) is export {
  my $msg = ($i ≥ 2**31 ?? $k.key !! $k.publicKey.key) ~ ser32($i);
  my ($left, $right) = .subbuf(0, 32), .subbuf(32) given 
    hmac(key => $k.chain-code, :$msg, hash => &sha512, block-size => 128);
  $k.new:
    depth          => $k.depth + 1,
    fingerprint    => (rmd160 sha256 $k.publicKey.key)
			.subbuf(0, 4)
			.list.reduce(256 * * + *),
    child-number   => $i,
    chain-code     => $right,
    key            => blob8.new(0) ~
                      ser256((parse256($left) + $k.Int) mod Bitcoin::EC::G.order)
  ;
}
