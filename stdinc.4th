#ifndef _STDINC_4TH_
#define _STDINC_4TH_

( Arithmetic functions )
: dec 1 - ;
: inc 1 + ;

( Printing strings )
: print begin dup dup 0 <> if emit then 0 = until drop ;
: println print cr ;

#endif
