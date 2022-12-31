[![SparrowCI](https://ci.sparrowhub.io/project/gh-grondilu-bitcoin-raku-tools/badge)](https://ci.sparrowhub.io)

# Bitcoin raku tools

## Synopses

### Bitcoin
```raku
use Bitcoin;

# A private key is just a 256-bits integer
say ^2**256 .pick;

# mix it with the Bitcoin::PrivateKey role to add bitcoin-related methods
say my $key = ^2**256 .pick but Bitcoin::PrivateKey;

# There is a very small chance that mixing will fail as the key range does not
# quite go up to 2**256.  See documentation about secp256k1 for details.
my $key = 2**256 - 123 but Bitcoin::PrivateKey;  # dies with 'index out of range' message

# Otherwise, the Bitcoin::PrivateKey role mainly defines a wif and address method.
# So far, the generated address is always the P2PKH one.
say $key.wif;                     # L2sJY3d2U5kzZSXrREDACTEDW3TbBidYQPvt3REDACTED84e55wr
say $key.wif: :uncompressed;      # 5K6WMB7MGenK2TdScgSp2B5REDACTEDyxbeamdaREDACTEDPvbt
say $key.address;                 # 1JGoEGREDACTEDzGTBQhDu15pWa5WgDjLa
say $key.address: :uncompressed;  # 13UpWYvdnJZuMREDACTEDDTNQEsrLpyGWd
```

### BIP32

```raku
use BIP32;

# master key generation
#   - random, defaut entropy is 16 bytes
my MasterKey $m .= new;
#   - from a seed
my MasterKey $m .= new: my $seed = blob8.new: ^256 .roll: 32;

# key derivation
print $m/0;
print $m/0/0h;
```

### BIP39

```raku
use BIP39;

# create random mnemonics
say Mnemonic.new: 24;     # twenty four words
say Mnemonic.new;         # default is twelve

# create mnemonics from entropy
my blob8 $entropy .= new: 0 xx 16;

say Mnemonic.new: $entropy;    # (abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about)

%*ENV<LANG>='zh_CN';
say Mnemonic.new: $entropy;    # 的的的的的的的的的的的在

%*ENV<LANG>='fr_FR';                               
say Mnemonic.new: $entropy;    # (abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille) 

# Build a mnemonic object from a mnemonic words list
my Mnemonic $mnemonic .= new: <harbor control census bulb absurd observe host country bleak divorce fall neglect>;

# extract a BIP32-compatible seed from a mnemonic object
say $mnemonic.Blob;
# same, but with a passphrase
say $mnemonic.Blob('sezame');
```

## LICENSE

This library is free software.  It is released on the same terms as Raku
itself.  See the 'COPYRIGHT' and 'LICENSE' files for more information.

THIS SOFTWARE IS PROVIDED WITH NO WARRANTY WHATSOEVER.  USE AT YOUR OWN RISK.
