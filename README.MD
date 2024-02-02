# WARNING!

This program is for **educational use only** and has not been vetted for correctness,
conformity, or undefined behavior. Do not use this in a production environment.

## Description

This code implements a simple SHA256 hashing utility. Emphasis has been placed on
clarity over performance. Testing is limited to Intel x86 and Apple Silicon on macOS
in the terminal and Linux/Unix systems. While the code is written in pure C++
and should be portable, no such promise is made.

The standard being implemented can be found in [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

## Compilation

To compile the source, simply type the following at the command line prompt:

```
c++ -std=c++20 -O3 -o sha256 sha256.cpp
```
## Copying

This software is placed into the public domain by the author.

