package neo;

public final class OpCode {
    // Constants
    public static final byte PUSH0    		= 0x00; // An empty array of bytes is pushed onto the stack.
    public static final byte PUSHF     		= PUSH0;
    public static final byte PUSHBYTES1  	= 0x01; // 0x01-0x4B The next opcode bytes is data to be pushed onto the stack
    public static final byte PUSHBYTES75 	= 0x4B;
    public static final byte PUSHDATA1   	= 0x4C; // The next byte contains the number of bytes to be pushed onto the stack.
    public static final byte PUSHDATA2   	= 0x4D; // The next two bytes contain the number of bytes to be pushed onto the stack.
    public static final byte PUSHDATA4   	= 0x4E; // The next four bytes contain the number of bytes to be pushed onto the stack.
    public static final byte PUSHM1      	= 0x4F; // The number -1 is pushed onto the stack.
    public static final byte PUSH1       	= 0x51; // The number 1 is pushed onto the stack.
    public static final byte PUSHT       	= PUSH1;
    public static final byte PUSH2       	= 0x52; // The number 2 is pushed onto the stack.
    public static final byte PUSH3       	= 0x53; // The number 3 is pushed onto the stack.
    public static final byte PUSH4       	= 0x54; // The number 4 is pushed onto the stack.
    public static final byte PUSH5       	= 0x55; // The number 5 is pushed onto the stack.
    public static final byte PUSH6       	= 0x56; // The number 6 is pushed onto the stack.
    public static final byte PUSH7       	= 0x57; // The number 7 is pushed onto the stack.
    public static final byte PUSH8       	= 0x58; // The number 8 is pushed onto the stack.
    public static final byte PUSH9       	= 0x59; // The number 9 is pushed onto the stack.
    public static final byte PUSH10      	= 0x5A; // The number 10 is pushed onto the stack.
    public static final byte PUSH11      	= 0x5B; // The number 11 is pushed onto the stack.
    public static final byte PUSH12      	= 0x5C; // The number 12 is pushed onto the stack.
    public static final byte PUSH13      	= 0x5D; // The number 13 is pushed onto the stack.
    public static final byte PUSH14      	= 0x5E; // The number 14 is pushed onto the stack.
    public static final byte PUSH15      	= 0x5F; // The number 15 is pushed onto the stack.
    public static final byte PUSH16      	= 0x60; // The number 16 is pushed onto the stack.

    // Flow control
    public static final byte NOP      		= 0x61; // Does nothing.
    public static final byte JMP      		= 0x62;
    public static final byte JMPIF    		= 0x63;
    public static final byte JMPIFNOT 		= 0x64;
    public static final byte CALL     		= 0x65;
    public static final byte RET      		= 0x66;
    public static final byte APPCALL  		= 0x67;
    public static final byte SYSCALL  		= 0x68;
    public static final byte TAILCALL 		= 0x69;

    // Stack
    public static final byte DUPFROMALTSTACK 	= 0x6A;
    public static final byte TOALTSTACK      	= 0x6B; // Puts the input onto the top of the alt stack. Removes it from the main stack.
    public static final byte FROMALTSTACK    	= 0x6C; // Puts the input onto the top of the main stack. Removes it from the alt stack.
    public static final byte XDROP           	= 0x6D;
    public static final byte XSWAP           	= 0x72;
    public static final byte XTUCK           	= 0x73;
    public static final byte DEPTH           	= 0x74; // Puts the number of stack items onto the stack.
    public static final byte DROP            	= 0x75; // Removes the top stack item.
    public static final byte DUP             	= 0x76; // Duplicates the top stack item.
    public static final byte NIP             	= 0x77; // Removes the second-to-top stack item.
    public static final byte OVER            	= 0x78; // Copies the second-to-top stack item to the top.
    public static final byte PICK            	= 0x79; // The item n back in the stack is copied to the top.
    public static final byte ROLL            	= 0x7A; // The item n back in the stack is moved to the top.
    public static final byte ROT             	= 0x7B; // The top three items on the stack are rotated to the left.
    public static final byte SWAP            	= 0x7C; // The top two items on the stack are swapped.
    public static final byte TUCK            	= 0x7D; // The item at the top of the stack is copied and inserted before the second-to-top item.

    // Splice
    public static final byte CAT    		= 0x7E; // Concatenates two strings.
    public static final byte SUBSTR 	    = 0x7F; // Returns a section of a string.
    public static final byte LEFT   		= (byte)0x80; // Keeps only characters left of the specified point in a string.
    public static final byte RIGHT  		= (byte)0x81; // Keeps only characters right of the specified point in a string.
    public static final byte SIZE   		= (byte)0x82; // Returns the length of the input string.

    // Bitwise logic
    public static final byte INVERT 	    = (byte)0x83; // Flips all of the bits in the input.
    public static final byte AND    		= (byte)0x84; // Boolean and between each bit in the inputs.
    public static final byte OR     		    = (byte)0x85; // Boolean or between each bit in the inputs.
    public static final byte XOR    		= (byte)0x86; // Boolean exclusive or between each bit in the inputs.
    public static final byte EQUAL  		= (byte)0x87; // Returns 1 if the inputs are exactly equal, 0 otherwise.
    //OP_EQUALVERIFY = 0x88, // Same as OP_EQUAL, but runs OP_VERIFY afterward.
    //OP_RESERVED1 = 0x89, // Transaction is invalid unless occuring in an unexecuted OP_IF branch
    //OP_RESERVED2 = 0x8A, // Transaction is invalid unless occuring in an unexecuted OP_IF branch

    // Arithmetic
    // Note: Arithmetic inputs are limited to signed 32-bit integers, but may overflow their output.
    public static final byte INC         	= (byte)0x8B; // 1 is added to the input.
    public static final byte DEC         	= (byte)0x8C; // 1 is subtracted from the input.
    public static final byte SIGN        	= (byte)0x8D;
    public static final byte NEGATE      	= (byte)0x8F; // The sign of the input is flipped.
    public static final byte ABS         	= (byte)0x90; // The input is made positive.
    public static final byte NOT         	= (byte)0x91; // If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
    public static final byte NZ          	= (byte)0x92; // Returns 0 if the input is 0. 1 otherwise.
    public static final byte ADD         	= (byte)0x93; // a is added to b.
    public static final byte SUB         	= (byte)0x94; // b is subtracted from a.
    public static final byte MUL         	= (byte)0x95; // a is multiplied by b.
    public static final byte DIV         	= (byte)0x96; // a is divided by b.
    public static final byte MOD         	= (byte)0x97; // Returns the remainder after dividing a by b.
    public static final byte SHL         	= (byte)0x98; // Shifts a left b bits, preserving sign.
    public static final byte SHR         	= (byte)0x99; // Shifts a right b bits, preserving sign.
    public static final byte BOOLAND     	= (byte)0x9A; // If both a and b are not 0, the output is 1. Otherwise 0.
    public static final byte BOOLOR      	= (byte)0x9B; // If a or b is not 0, the output is 1. Otherwise 0.
    public static final byte NUMEQUAL    	= (byte)0x9C; // Returns 1 if the numbers are equal, 0 otherwise.
    public static final byte NUMNOTEQUAL 	= (byte)0x9E; // Returns 1 if the numbers are not equal, 0 otherwise.
    public static final byte LT          	= (byte)0x9F; // Returns 1 if a is less than b, 0 otherwise.
    public static final byte GT          	= (byte)0xA0; // Returns 1 if a is greater than b, 0 otherwise.
    public static final byte LTE         	= (byte)0xA1; // Returns 1 if a is less than or equal to b, 0 otherwise.
    public static final byte GTE         	= (byte)0xA2; // Returns 1 if a is greater than or equal to b, 0 otherwise.
    public static final byte MIN         	= (byte)0xA3; // Returns the smaller of a and b.
    public static final byte MAX         	= (byte)0xA4; // Returns the larger of a and b.
    public static final byte WITHIN      	= (byte)0xA5; // Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.

    // Crypto
    //RIPEMD160 = 0xA6, // The input is hashed using RIPEMD-160.
    public static final byte SHA1    		= (byte)0xA7; // The input is hashed using SHA-1.
    public static final byte SHA256  		= (byte)0xA8; // The input is hashed using SHA-256.
    public static final byte HASH160 		= (byte)0xA9;
    public static final byte HASH256 		= (byte)0xAA;
    //因为这个hash函数可能仅仅是csharp 编译时专用的
    public static final byte CSHARPSTRHASH32 	= (byte)0xAB;
    //这个是JAVA专用的
    public static final byte JAVAHASH32 		= (byte)0xAD;

    public static final byte CHECKSIG      		= (byte)0xAC;
    public static final byte CHECKMULTISIG 	= (byte)0xAE;

    // Array
    public static final byte ARRAYSIZE 	= (byte)0xC0;
    public static final byte PACK      		= (byte)0xC1;
    public static final byte UNPACK    		= (byte)0xC2;
    public static final byte PICKITEM  		= (byte)0xC3;
    public static final byte SETITEM   		= (byte)0xC4;
    public static final byte NEWARRAY  		= (byte)0xC5; //用作引用類型
    public static final byte NEWSTRUCT 	= (byte)0xC6; //用作值類型

    public static final byte SWITCH 		= (byte)0xD0;

    // Exceptions
    public static final byte THROW      	= (byte)0xF0;
    public static final byte THROWIFNOT 	= (byte)0xF1;
}
