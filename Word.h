#pragma once

#include <cstdint>
#include <iostream>

class Word {
private:
    uint32_t w;

public:
    // Constructors
    Word() : w(0) {}
    Word(uint32_t val) : w(val) {}
    // Copy Constructor
    Word(const Word& other): w(other.w) {}
    // Destructor
    ~Word() {}

    // Getter and Setter methods
    inline uint32_t get() const { return w; }
    inline void set(unsigned int v) { w = static_cast<uint32_t>(v); }

    // Bitwise rotate left and right operations ; use -std=c++20 option
    inline Word rotl(int n) { return std::rotl(w, n); }
    inline Word rotr(int n) { return std::rotr(w, n); }

    static constexpr uint32_t ONE = 1; // Named constant

    // GetBit and SetBit methods
    inline bool getbit(int n) const { return (w >> n) & ONE; }
    inline void setbit(int n, bool b){
        if(b){
            w |= (ONE << n);
        }else{
            w &= ~(ONE << n);
        }
    }

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

    // + and - operators
    inline Word operator+(const Word& rhs) { return this->w + rhs.w; }
    inline Word operator+(const uint32_t rhs) { return this->w + rhs; }
    inline Word operator-(const Word& rhs) { return this->w - rhs.w; }
    inline Word operator-(const uint32_t rhs) { return this->w - rhs; }

    // Bit shift left (<<) operator overloads
    inline Word operator<<(const Word& rhs) { return w << rhs.w; }
    inline Word operator<<(const uint32_t rhs) { return w << rhs; }

    // Bit shift right (>>) operator overloads
    inline Word operator>>(const Word& rhs) { return w >> rhs.w; }
    inline Word operator>>(const uint32_t rhs) { return w >> rhs; }

    // Bit shift assignment left (<<=) operator overloads
    inline Word& operator<<=(const Word& rhs) { 
        w <<= rhs.w;
        return *this;
     }
     inline Word& operator<<=(const uint32_t rhs) {
         w <<= rhs;
         return *this; 
     }

     // Bit shift assignment right (>>=) operator overloads
     inline Word& operator>>=(const Word& other){
         this->w >>= other.w;
         return *this;
     }
     inline Word& operator>>=(const uint32_t val){
         this->w >>= val;
         return *this;
      }  

    // Overloaded output operator for debugging
    friend std::ostream& operator<<(std::ostream& os, const Word& obj) {
        os << obj.w;
        return os;
    }

};

