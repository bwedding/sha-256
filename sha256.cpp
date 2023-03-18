///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//		     SHA-256 As defined by NIST.FIPS.180-4                   //
//                     A great visualizer can be found at                    //
//                                                                           //
//                        https://sha256algorithm.com                        //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#include <vector>
#include <valarray>
#include <string>
#include <iostream>
#include <fstream>

using namespace std;

template<typename T>
class Vec : public std::vector<T> {
public:
    using vector<T>::vector;

    T& operator[](int i)
        { return vector<T>::at(i); }

    const T& operator[](int i) const
        { return vector<T>::at(i); }
};

typedef uint32_t Word;
typedef const vector<Word> SHA256_Constants;
typedef Vec<Word> Digest;
typedef Vec<unsigned char> Message;
typedef Vec<Word> Block;
typedef Vec<Word> Schedule;

string wordToHexString(Word w) {
    const char lut[] = "0123456789abcdef";
    const Word nibbles[] = {0xf0000000,0x0f000000,0x00f00000,0x000f0000,
        0x0000f000,0x00000f00,0x000000f0,0x0000000f};
    const char shifts[] = {28,24,20,16,12,8,4,0};
    string hex = "";

    for (char j = 0; j < 8; j++) {
        Word nibble = w & nibbles[j];
        nibble >>= shifts[j];
        hex += lut[nibble];
    }
   
    return hex;
}

string wordToBinaryString(Word w) {
    string bits = "";

    for (char j = 0; j < 32; j++) {
        Word x = w & 0x80000000;
        bits += x ? "1" : "0";
        w <<= 1;
    }

    return bits;
}

string byteToBinaryString(unsigned char b) {
    string bits = "";

    for (char j = 0; j < 8; j++) {
        int i = b & 0x80;
        bits += i ? "1" : "0";
        b <<= 1;
    }

    return bits;
}

string getDigestAsHex(const Digest& digest) {
    string hex = "";

    for (auto w : digest) {
        hex += wordToHexString(w);
    }
   
    return hex;
}

string getDigestAsBin(const Digest& digest) {
    string bin = "";

    for (auto w : digest) {
        bin += wordToBinaryString(w);
    }

    return bin;
}

string getBlockAsBin(const Block& b) {
    string bits = "";

    for (auto w : b) {
        bits += wordToBinaryString(w);
    }
    
    return bits;
}   

inline Word reverseByteOrder(Word x) {
    return ((x << 24) & 0xff000000) |
           ((x << 8)  & 0x00ff0000) |
           ((x >> 8)  & 0x0000ff00) |
           ((x >> 24) & 0x000000ff);
}

string insertSpaceAfterEighthChar(string inputStr)
{
    auto iter = inputStr.begin() + 8;
    while (iter != inputStr.end())
    {
        iter = inputStr.insert(iter, ' ');
        iter += 9;
    }
    return inputStr;
}

string replaceEighthSpaceWithNewline(string inputStr)
{
    int spaceCount = 0;
    for (int i = 0; i < inputStr.length(); i++)
    {
        if (inputStr[i] == ' ')
        {
            spaceCount++;
            if (spaceCount == 8)
            {
                inputStr[i] = '\n';
                spaceCount = 0;
            }
        }
    }
    return inputStr;
}

inline Word addmod32(const valarray<uint64_t>& va) {
    uint64_t t = va.sum();
    Word w = t & 0xffffffff;
    return w;
}

// Section 4.4.2 SHA-256 Constants
//
// These words represent the first thirty-two bits of the fractional parts of
// the cube roots of the first sixty-four prime numbers. In hex, these constant
// words are (from left to right)

SHA256_Constants K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

// Section 5.3.3 SHA-256
//
// For SHA-256, the initial hash value, H(0), shall consist of the following 
// eight 32-bit words, in hex. These words were obtained by taking the first
// thirty-two bits of the fractional parts of the square roots of the first
// eight prime numbers.

const Digest H0 = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

// Section 4.1.2 SHA-256 Functions
//
// SHA-256 uses six logical functions, where each function operates on 32-bit
// words which are represented as x, y, and z, The result of each function is
// a new 32 bit word.
//
// Ch and Maj are apperently for Choose and Major, respectively.
// https://crypto.stackexchange.com/questions/5358/what-does-maj-and-ch-mean-in-sha-256-algorithm

inline Word Ch(Word x, Word y, Word z) {return (x&y)^((~x)&z);}         // 4.2
inline Word Maj(Word x, Word y, Word z) {return (x&y)^(x&z)^(y&z);}     // 4.3
inline Word ROTR(int n, Word x) {return (x>>n)|(x<<(32-n));}            // 3.2.4
inline Word SHR(int n, Word x) {return (x>>n);}                         // 3.2.3

inline Word SIGMA0(Word x) {return ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x);} // 4.4
inline Word SIGMA1(Word x) {return ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x);} // 4.5
inline Word sigma0(Word x) {return ROTR(7,x) ^ ROTR(18,x) ^ SHR(3,x);}   // 4.6
inline Word sigma1(Word x) {return ROTR(17,x) ^ ROTR(19,x) ^ SHR(10,x);} // 4.7

// 5.1 Padding The Message
// The purpose of this padding is to ensure that the padded message is a multiple
// of 512 bits. Padding can be inserted before hash computation begins on a
// message, or at any other time during the hash computation prior to processing
// the block(s) that will contain the padding.

const Message pad(uint64_t l) {
    Message padding = {0x80};

    if (l == 0) {
        padding.resize(56,0);
	cout << "Zero length message." << endl;
    } else if (l % 512 == 0) {
	cout << "Message is already mod 512 length." << endl;
	return padding = {};
    } else if (l % 512  > 440) {
	cout << "Last message block doesn't have enough room "
	     << "for padding." << endl
	     << "We will add an extra number of zeros to bring the " << endl
	     << "message length up to mod 512 length." << endl << endl;
	int k = 960 - (l % 1024 + 1); // pad remainder of block and add new block
	padding.resize(k/8 + 1, 0);
    } 
    else {
	cout << "Add 448 - (l % 512 + 1) zero bits to padding." << endl;
	int k = 448 - (l % 512 + 1);
        padding.resize(k/8 + 1, 0);
    }

    union {
        uint64_t m;
        unsigned char b[8];
    } bad_wolf;
    
    bad_wolf.m = l;
    // reverse byte order for little endian machines like x86 and Apple Si
    for (int i = 7; i > -1; i--) padding.push_back(bad_wolf.b[i]);

    cout << "Padding bits:" << endl;
    string b = "";
    for (auto e : padding)
	b += byteToBinaryString(e);
    b = insertSpaceAfterEighthChar(b);
    b = replaceEighthSpaceWithNewline(b);
    cout << b << endl;
    
    return padding;
}

// 6.2.2 SHA-256 Hash Computation
// Prepare the message schedule

Schedule schedule(const Block& M, int blocknum) {
    Schedule W;

    W.reserve(64);

    cout << "Block " << blocknum << ":" << endl;
    string bits = "";
    for (auto w : M) {
        bits += wordToBinaryString(w);
    }

    bits = insertSpaceAfterEighthChar(bits);
    bits = replaceEighthSpaceWithNewline(bits);

    cout << bits << endl << endl;
    
    int t = 0;

    do {
        W.push_back(M[t]);
        cout << "W" << t << ": " << wordToBinaryString(M[t]) 
	     << " K" << t << ": " << wordToBinaryString(K[t]) << endl;
        t++;
    } while(t < 16);
    do {
        Word w = addmod32({sigma1(W[t-2]),W[t-7],sigma0(W[t-15]),W[t-16]});
        W.push_back(w);
        cout << "W" << t << ": " << wordToBinaryString(w) 
	     << " K" << t << ": " << wordToBinaryString(K[t]) << endl;
        t++;
    } while (t < 64);

    cout << endl;
    
    return W;
}

Digest runschedule(const Schedule& W, Digest& H) {
    Word a = H[0], b = H[1], c = H[2], d = H[3],
    e = H[4], f = H[5], g = H[6], h = H[7];
    
    for (int t = 0; t < 64; t++) {
        Word T1 = addmod32({h,SIGMA1(e),Ch(e,f,g),K[t],W[t]});
        Word T2 = addmod32({SIGMA0(a),Maj(a,b,c)});
        h = g; g = f; f = e; e = addmod32({d,T1}); d = c; c = b; 
        b = a; a = addmod32({T1,T2});
    }

    cout << endl;
    
    H[0] = addmod32({a , H[0]});
    H[1] = addmod32({b , H[1]});
    H[2] = addmod32({c , H[2]});
    H[3] = addmod32({d , H[3]});
    H[4] = addmod32({e , H[4]});
    H[5] = addmod32({f , H[5]});
    H[6] = addmod32({g , H[6]});
    H[7] = addmod32({h , H[7]});
    
    return H;
}

Digest message(Message& msg) {
    uint64_t  messagelength = msg.size() * 8;
    Digest digest = H0;
    
    const Message padding = pad(messagelength);
    
    for (auto e : padding) msg.push_back(e);
    
    cout << "Message Length in bits: " << messagelength << "\n";
    cout << "Padded Length in bits: " << msg.size() * 8 << "\n";
    
    // Parse the message 64 bytes at a time and process each block
    int i = 0, j = 0, k = 0;
    do {
        Block B = {};
        Word w = 0;
        B.reserve(16);
        
        do {
	    unsigned char a, b, c, d;
            a = msg[i++]; b = msg[i++]; c = msg[i++]; d = msg[i++];
            w = w | a; w <<= 8;
            w = w | b; w <<= 8;
            w = w | c; w <<= 8;
            w = w | d;
            B.push_back(w);
            w = 0;
            j++;
        } while (j < 16);

        Schedule s = schedule(B,k++);
        digest = runschedule(s, digest);
	j = 0;
    } while (i < msg.size());
    
    return digest;
}

Digest hashDigest(const Digest& d) {
    Digest digest = H0;
    const Digest pad = {0x80000000,0x00000000,0x00000000,0x00000000,
                        0x00000000,0x00000000,0x00000000,0x00000200};
    Block B = {};
    B.reserve(16);

    for (auto w : d) B.push_back(w);
    for (auto w : pad) B.push_back(w);

    Schedule s = schedule(B,0);
    return runschedule(s, digest);
}

vector<string> arguments(int argc, char* argv[]) {
    vector<string> res;

    for (int i = 1; i < argc; i++)
        res.push_back(argv[i]);

    return res;
}

int main(int argc, char* argv[]) {
try {
    vector<string> args = arguments(argc, argv);

    if (argc == 1) {
	cout << "SHA-256 algorithm for educational purposes only!" << endl
	     << endl << "$ sha256 [-] file1 [file2 ...]" << endl << endl
	     << "Reads each file and provides a SHA-256 digest." << endl
	     << "If the first argument is a - then each file will be " << endl
	     << "hashed twice. Bitcoin does this sha256(sha256(data))." << endl
	     << endl << "The output is a text hex representation of the "
	     << "SHA-256 message digest." << endl;
	return 0;
    }

    Message msg = {};
    msg.reserve(1024);

    bool doublehash = false;
    for (auto file : args) {
	char ch = 0;

	if (file == string("-")) {
            doublehash = true;
	    continue;
	}

        ifstream infile(file, ios::binary);

        while (infile.read(&ch, 1))
            msg.push_back((unsigned char)ch);

	infile.close();
        Digest digest = message(msg);

	if (doublehash) digest = hashDigest(digest);

	cout << file;
	if (doublehash) cout << " double hashed";
	cout << endl;
        cout << "Digest = " << getDigestAsHex(digest) << endl;
        cout << "Binary =" << endl
	     << replaceEighthSpaceWithNewline(
		   insertSpaceAfterEighthChar(getDigestAsBin(digest)))
	     << endl << endl;
	msg = {};
    }
}
catch (out_of_range) {
    cerr << "range error" << endl;
}
catch (...) {
    cerr << "unknown exception thrown" << endl;
}

    return 0;
}
