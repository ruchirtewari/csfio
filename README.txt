Verify for x of different sizes, the invariant property that
	Decrypt(Encrypt(x)) == x
This verification leads to handling of additional edge cases around read and lseek.

The challenge lies in the changing of the file size of the encrypted file compared to the original. 
This is because of a) fixed size enc-header added to each page  b) the last page having a different size. 

Added more comments, magic and validation code.
