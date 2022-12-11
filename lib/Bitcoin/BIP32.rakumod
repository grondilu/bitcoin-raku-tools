unit module Bitcoin::BIP32;
use Digest::HMAC:auth("Lucien Grondin");
use Digest::SHA2;

our constant %version-prefixes =
  mainnet => %(public => 0x0488B21E, private => 0x0488ADE4),
  testnet => %(public => 0x043587CF, private => 0x04358394)
  ;

sub postfix:<h>(UInt $i) is export { $i + 2**31 }

sub ser32(uint32 $i --> blob8) { blob8.new: $i.polymod(256 xx 3).reverse; }
sub ser256(UInt  $p --> blob8) { blob8.new: $p.polymod(256 xx 31).reverse; }

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
}

sub N(PrivateExtendedKey $key --> PublicExtendedKey) is export { $key.publicKey }

class MasterKey is PrivateExtendedKey is export {
  multi method new(Blob $seed) {
    my $sha512 = hmac
      key => "Bitcoin seed",
      msg => $seed,
      hash => &sha512, block-size => 128;
    my ($Il, $Ir) = map { $sha512.subbuf($_, 32) }, 0, 32;

    PrivateExtendedKey.new:
      depth        => 0,
      fingerprint  => 0,
      child-number => 0,
      chain-code   => blob8.new(@$Ir),
      key          => blob8.new(0, |@$Il)
    ;
  }
}

multi infix:</>(PrivateExtendedKey $ek, UInt $i) is export {
  my $key = $ek.chain-code;
  my $msg = $i ≥ 2**31 ?? blob8.new(0) ~ $ek.key !! $ek.key;
  $msg ~= ser32($i);
  my $I = hmac(:$key, :$msg, hash => &sha512, block-size => 128);
  return $I;
}
