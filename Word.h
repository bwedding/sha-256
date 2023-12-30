/*******************************************************************************
 *                                   Word.h                                    *
 *                              Author: Fudmottin                              *
 *                                                                             *
 * This software is provided 'as-is', without any express or implied warranty. *
 * In no event will the authors be held liable for any damages arising from    *
 * the use of this software.                                                   *
 *                                                                             *
 * Permission is hereby granted, free of charge, to any person obtaining a     *
 * copy of this software and associated documentation files (the "Software"),  *
 * to deal in the Software without restriction, including without limitation   *
 * the rights to use, copy, modify, merge, publish, distribute, sublicense and *
 * or sell copies of the Software.                                             *
 *                                                                             *
 * The Word class is a simple lightweight wrapper for uint32_t. It is intended *
 * to work like a uint32_t for cryptography. That said, not every possible     *
 * conversion to uint32_t is defined. Sometimes it will be necessary to use    *
 * the get() method to return the wrapped uint32_t value. In addition to       *
 * traditional get() and set() methods, assignment is supported. You can also  *
 * create a Word object using the constructor: Word w(42).                     *
 *                                                                             *
 * Due to properties of Word object, two seemingly equal values may not        *
 * actually be equal unless their type is either Word or uint32_t. Size        *
 * matters!                                                                    *
 *                                                                             *
 *              This file has been placed into The Public Domain               *
 *                                                                             *
 ******************************************************************************/

#pragma once

#include <cstdint>
#include <iostream>

class Word {
private:
    uint32_t w;
    static constexpr uint32_t ONE = 1; // Named constant

public:
    // Default constructor initializes internal representation (w) to zero.
    Word() : w(0) {}

    // Constructor that allows initialization with an unsigned int value.
    Word(uint32_t val) : w(val) {}

    // Copy constructor which copies value from another Word object into this one.
    Word(const Word& other): w(other.w) {}

    // Destructor - currently does nothing but included for completeness.
    ~Word() {}

    // Getter and Setter methods
    inline uint32_t get() const { return w; }
    inline void set(unsigned int v) { w = static_cast<uint32_t>(v); }

    // Bitwise rotate left and right operations ; use -std=c++20 option
    inline Word rotl(int n) { return std::rotl(w, n); }
    inline Word rotr(int n) { return std::rotr(w, n); }

    // GetBit and SetBit methods
    inline bool getbit(int n) const { return (w >> n) & ONE; }
    inline void setbit(int n, bool b){
        b ? w |= (ONE << n) : w &= ~(ONE << n);
    }

    // FlipBit method
    inline void flipbit(int n) {setbit(n, ~getbit(n));}

    // comparison operators
    inline bool operator==(const Word& rhs){return this->w == rhs.w;}
    inline bool operator==(const uint32_t rhs){return this->w == rhs;}
    inline bool operator!=(const Word& rhs){return this->w != rhs.w;}
    inline bool operator!=(const uint32_t rhs){return this->w != rhs;}


    // logical operators
    inline Word operator|(const Word& rhs){return this->w | rhs.w;}
    inline Word operator|(const uint32_t rhs){return this->w | rhs;}

    inline Word operator&(const Word& rhs){return this->w & rhs.w;}
    inline Word operator&(const uint32_t rhs){return this->w & rhs;}

    inline Word operator^(const Word& rhs){return this->w ^ rhs.w;}
    inline Word operator^(const uint32_t rhs){return this->w ^ rhs;}

    inline Word operator<<(const Word& rhs) { return w << rhs.w; }
    inline Word operator<<(const uint32_t rhs) { return w << rhs; }

    inline Word operator>>(const Word& rhs) { return w >> rhs.w; }
    inline Word operator>>(const uint32_t rhs) { return w >> rhs; }

    inline Word operator~() const { return Word(~w); }

    // assignmennt operators
    inline Word& operator=(const uint32_t val){
        this->w = val;
        return *this;
    }
    inline Word& operator=(const Word& other){
        this->w = other.w;         
        return *this;
    }

    inline Word& operator|=(const uint32_t val){
        this->w |= val;
        return *this;
    }
    inline Word& operator|=(const Word& other){
        this->w |= other.w;
        return *this;
    }

    inline Word& operator&=(const uint32_t val){
      this->w &= val;
      return *this;
    }
    inline Word& operator&=(const Word& other){
      this->w &= other.w;
      return *this;
    }

    inline Word& operator^=(const uint32_t val){
      this->w ^= val;
      return *this;
    }
    inline Word& operator^=(const Word& other){
      this->w ^= other.w;
      return *this;
    }

    inline Word& operator<<=(const Word& rhs) { 
        w <<= rhs.w;
        return *this;
    }
    inline Word& operator<<=(const uint32_t rhs) {
        w <<= rhs;
        return *this; 
    }

    inline Word& operator>>=(const Word& other){
        this->w >>= other.w;
        return *this;
    }
    inline Word& operator>>=(const uint32_t val){
        this->w >>= val;
        return *this;
    }  

    // + and - operators
    inline Word operator+(const Word& rhs) { return this->w + rhs.w; }
    inline Word operator+(const uint32_t rhs) { return this->w + rhs; }
    inline Word operator-(const Word& rhs) { return this->w - rhs.w; }
    inline Word operator-(const uint32_t rhs) { return this->w - rhs; }

    // Output opperator for std::ostream
    friend std::ostream& operator<<(std::ostream& os, const Word& obj) {
        os << obj.w;
        return os;
    }

};

