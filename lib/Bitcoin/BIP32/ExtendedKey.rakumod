unit role Bitcoin::BIP32::ExtendedKey;
use secp256k1;

method version returns uint32 {...}
method key returns Blob {...}
method Point returns Point {...}

method identifier returns Blob {
  #use Digest::SHA2;
  use Digest::OpenSSL;
  use Digest::RIPEMD;
  rmd160 sha256 self.Point.Blob;
}

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
method Str {
  use Base58;
  #use Digest::SHA2;
  use Digest::OpenSSL;
  given self.Blob {
    return Base58::encode $_ ~ (sha256 sha256 $_).subbuf(0, 4);
  }
}
