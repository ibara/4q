4q
==
`4q`, pronounced fork, is a compiler for a
[Forth](https://en.wikipedia.org/wiki/Forth_(programming_language))-like
programming language.

`4q` compiles Forth words into
[QBE](https://c9x.me/compile/)
intermediate language.

`4q` acts as both a compiler and compiler driver, enabling binaries to
be produced with a single command-line invocation.

`4q` is written in
[D](https://dlang.org/)
and can use any D compiler to build. The `configure` script will
autodetect the first D compiler it finds in order:
[LDC](https://wiki.dlang.org/LDC),
[GDC](https://wiki.dlang.org/GDC),
and
[DMD](https://wiki.dlang.org/DMD).

Building
--------
`4q` should be able to be built on any supported platform that can run
a D compiler.

```sh
$ ./configure
$ make
$ sudo make install
```

Supported platforms
-------------------
* macOS on both arm64 and x86\_64
* Linux (Ubuntu, others welcome) on x86\_64
* [FreeBSD](https://freebsd.org/) on amd64

LICENSE
-------
ISC license. See `LICENSE` for more details.
