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
#include <bit>


class Word {

    uint32_t w;
    static constexpr uint32_t ONE = 1; // Named constant

public:
    // Default constructor initializes internal representation (w) to zero.
    Word() : w(0) {}

    // Constructor that allows initialization with an unsigned int value.
    Word(const uint32_t val) : w(val) {}

    // Copy constructor which copies value from another Word object into this one.
    Word(const Word& other) : w(other.w) {}

    // Destructor - currently does nothing but included for completeness.
    ~Word() = default;

    // Getter and Setter methods
    [[nodiscard]] uint32_t get() const { return w; }
    void set(unsigned int v) { w = static_cast<uint32_t>(v); }

    // Bitwise rotate left and right operations ; use -std=c++20 option
    Word rotl(int n) const { return std::rotl(w, n); }
    Word rotr(int n) const { return std::rotr(w, n); }

    // These can be useful
    bool getbit(int n) const { return (w >> n) & ONE; }
    void setbit(int n) { w |= (ONE << n); }
    void unsetbit(int n) { w &= ~(ONE << n); }
    void flipbit(int n) { w ^= (ONE << n); }

    // comparison operators
    bool operator==(const Word& rhs) const { return this->w == rhs.w; }
    bool operator==(const uint32_t rhs) const { return this->w == rhs; }
    bool operator!=(const Word& rhs) const { return this->w != rhs.w; }
    bool operator!=(const uint32_t rhs) const { return this->w != rhs; }


    // logical operators
    Word operator|(const Word& rhs)  const { return this->w | rhs.w; }
    Word operator|(const uint32_t rhs)  const { return this->w | rhs; }

    Word operator&(const Word& rhs)  const { return this->w & rhs.w; }
    Word operator&(const uint32_t rhs) const { return this->w & rhs; }

    Word operator^(const Word& rhs)  const { return this->w ^ rhs.w; }
    Word operator^(const uint32_t rhs)  const { return this->w ^ rhs; }

    Word operator<<(const Word& rhs) const { return w << rhs.w; }
    Word operator<<(const uint32_t rhs) const { return w << rhs; }

    Word operator>>(const Word& rhs) const { return w >> rhs.w; }
    Word operator>>(const uint32_t rhs) const { return w >> rhs; }

    Word operator~() const { return Word(~w); }

    // assignment operators
    Word& operator=(const uint32_t val) {
        this->w = val;
        return *this;
    }
    Word& operator=(const Word& other) = default;

    Word& operator|=(const uint32_t val) {
        this->w |= val;
        return *this;
    }
    Word& operator|=(const Word& other) {
        this->w |= other.w;
        return *this;
    }

    Word& operator&=(const uint32_t val) {
        this->w &= val;
        return *this;
    }
    Word& operator&=(const Word& other) {
        this->w &= other.w;
        return *this;
    }

    Word& operator^=(const uint32_t val) {
        this->w ^= val;
        return *this;
    }
    Word& operator^=(const Word& other) {
        this->w ^= other.w;
        return *this;
    }

    Word& operator<<=(const Word& rhs) {
        w <<= rhs.w;
        return *this;
    }
    Word& operator<<=(const uint32_t rhs) {
        w <<= rhs;
        return *this;
    }

    Word& operator>>=(const Word& other) {
        this->w >>= other.w;
        return *this;
    }
    Word& operator>>=(const uint32_t val) {
        this->w >>= val;
        return *this;
    }

    // + and - operators
    Word operator+(const Word& rhs) const { return this->w + rhs.w; }
    Word operator+(const uint32_t rhs) const { return this->w + rhs; }
    Word operator-(const Word& rhs) const { return this->w - rhs.w; }
    Word operator-(const uint32_t rhs) const { return this->w - rhs; }

    // * and / operators
    Word operator*(const Word& rhs) const { return this->w * rhs.w; }
    Word operator*(const uint32_t rhs) const { return this->w * rhs; }
    Word operator/(const Word& rhs) const { return this->w / rhs.w; }
    Word operator/(const uint32_t rhs) const { return this->w / rhs; }

    // % operator
    Word operator%(const Word& rhs) const { return this->w % rhs.w; }
    Word operator%(const uint32_t rhs) const { return this->w % rhs; }

    // Output opperator for std::ostream
    friend std::ostream& operator<<(std::ostream& os, const Word& obj) {
        os << obj.w;
        return os;
    }

};
