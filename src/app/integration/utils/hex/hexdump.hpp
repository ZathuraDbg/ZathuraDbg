#ifndef ZATHURA_HEXDUMP_HPP
#define ZATHURA_HEXDUMP_HPP

#include <cctype>
#include <iomanip>
#include <ostream>

template <unsigned rowSize, bool showAscii>
struct hexInfo
{
    hexInfo(const void* data, unsigned length) :
            mData(static_cast<const unsigned char*>(data)), mLength(length) { }
    const unsigned char* mData;
    const unsigned mLength;
};

template <unsigned rowSize, bool showAscii>
std::stringstream dump(const hexInfo<rowSize, showAscii>& dump)
{
    std::stringstream out;
    out.fill('0');
    for (int i = 0; i < dump.mLength; i += rowSize)
    {
        out << "0x" << std::setw(6) << std::hex << i << ": ";
        for (int j = 0; j < rowSize; ++j)
        {
            if (i + j < dump.mLength)
            {
                out << std::hex << std::setw(2) << static_cast<int>(dump.mData[i + j]) << " ";
            }
            else
            {
                out << "   ";
            }
        }

        out << " ";
        if (showAscii)
        {
            for (int j = 0; j < rowSize; ++j)
            {
                if (i + j < dump.mLength)
                {
                    if (std::isprint(dump.mData[i + j]))
                    {
                        out << static_cast<char>(dump.mData[i + j]);
                    }
                    else
                    {
                        out << ".";
                    }
                }
            }
        }
        out << std::endl;
    }
    return out;
}

std::string hexDump(const char* data, unsigned int length)
{
    return dump<8, true>({data, length}).str();
}

#endif
