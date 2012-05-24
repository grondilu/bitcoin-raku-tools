class Bitcoin::Script;

has Buf $.buffer;

method new(Buf $buffer) { self.Mu::new: :buffer($buffer) }
method gist { 'Bitcoin::Script:<' ~ join(' ', $.buffer.list) ~ '>' }

our enum Codes <
    OP_0		

    OP_PUSHDATA1	
    OP_PUSHDATA2	
    OP_PUSHDATA4	
    OP_1NEGATE		
			
    OP_NOP		
    OP_IF		
    OP_NOTIF		
    OP_ELSE 		
    OP_ENDIF 		
    OP_VERIFY		
    OP_RETURN		
			
    OP_TOALTSTACK   	
    OP_FROMALTSTACK 	
    OP_DROP  		
    OP_ROT   		
    OP_SWAP  		
    OP_TUCK  		
    OP_2DROP 		
    OP_2DUP  		
    OP_3DUP  		
    OP_2OVER 		
    OP_2ROT  		
    OP_2SWAP 		
    OP_IFDUP 		
    OP_DEPTH 		
    OP_DUP   		
    OP_NIP   		
    OP_OVER  		
    OP_PICK  		
    OP_ROLL  		
			
    OP_EQUAL		
    OP_EQUALVERIFY	
			
    OP_RIPEMD160	
    OP_SHA1     	
    OP_SHA256   	
    OP_HASH160  	
    OP_HASH256  	
			
    OP_CODESEPARATOR    
    OP_CHECKSIG		
    >;

