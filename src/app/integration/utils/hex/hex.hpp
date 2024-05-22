#ifndef HEXDUMP_HPP
#define HEXDUMP_HPP

#include <cctype>
#include <iomanip>
#include <ostream>

#define RowSize 8

struct hexStruct
{
    hexStruct(const void* data, unsigned long length) :
        mData(static_cast<const unsigned char*>(data)), mLength(length) { }
    const unsigned char* mData;
    const unsigned mLength;
};

static std::string hexlify(const hexStruct& dump) {
    std::string result;
    result.reserve(dump.mLength);

    for (int i = 0; i < dump.mLength; ++i) {
        result += static_cast<char>(dump.mData[i]);
    }

    return result;
}

#endif // HEXDUMP_HPP

