unit role BIP32::xkey;
use secp256k1;

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
