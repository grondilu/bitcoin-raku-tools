use Bitcoin::BIP32::ExtendedKey;
unit class Bitcoin::BIP32::ExtendedKey::Private does Bitcoin::BIP32::ExtendedKey;
use secp256k1;

has UInt $.key handles Int;
submethod TWEAK { $!key %= G.order }

method version { %*ENV<BITCOIN_TEST> ?? 0x04358394 !! 0x0488ADE4; }
method Point { self.Int*G }
method key returns Blob { blob8.new: $!key.polymod(256 xx 32).reverse }

