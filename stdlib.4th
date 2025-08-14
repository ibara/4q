#ifndef _STDLIB_4TH_
#define _STDLIB_4TH_

: dec 1 - ;
: inc 1 + ;
: write begin dup dup 0 <> if emit then 0 = until drop ;
: writeln write cr ;

#endif
