# Bitcoin raku tools

## Synopsis

```raku
use Bitcoin;

# A private key is just an integer in a particular range.
say key-range;  # 1..^115792[many more digits...]

# creating a private key is just picking an integer in that range
say my UInt $key = key-range.pick; # just a big integer

# Wallet Import Format
say WIF $key;               # L2sJY3d2U5kzZSXrREDACTEDW3TbBidYQPvt3REDACTED84e55wr
say WIF $key, :uncompressed # 5K6WMB7MGenK2TdScgSp2B5REDACTEDyxbeamdaREDACTEDPvbt

# P2PKH addresses
say P2PKH::address $key;                 # 1JGoEGREDACTEDzGTBQhDu15pWa5WgDjLa
say P2PKH::address $key, :uncompressed;  # 13UpWYvdnJZuMREDACTEDDTNQEsrLpyGWd

use Bitcoin::BIP32;

# master key generation from a seed
my MasterKey $m .= new: my $seed = blob8.new: ^256 .roll: 32;

# key derivation
print $m/0;
print $m/0/0h;

use Bitcoin::BIP39;

# create random mnemonics
say create-mnemonics 24;     # twenty four words
say create-mnemonics;        # default is twelve

# create mnemonics from entropy
say my @mnemo = entropy-to-mnemonics
    blob8.new: 0 xx 16;                 # (abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about)

%*ENV<LANG>='zh_CN';
say entropy-to-mnemonics(@mnemo).join;  # 的的的的的的的的的的的在

%*ENV<LANG>='fr_FR';                               
say entropy-to-mnemonics(@mnemo).join;  # (abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille) 

say mnemonics-to-seed @mnemo;  
```

## LICENSE

This library is free software.  It is released on the same terms as Raku
itself.  See the 'COPYRIGHT' and 'LICENSE' files for more information.

THIS SOFTWARE IS PROVIDED WITH NO WARRANTY WHATSOEVER.  USE AT YOUR OWN RISK.
