#include "nasm.hpp"
target targetArch;

bool saveAsmFile(std::string assembly){
    std::ofstream asmFile;
    asmFile.open(ASM_FILE_NAME, std::ios::out);
    if (!(asmFile.is_open())){
        std::perror("could not open the file");
        return false;
    }

    std::string firstLine = assembly.substr(0, 20);
    firstLine.erase(std::remove(firstLine.begin(), firstLine.end(), ' '), firstLine.end());

    if (firstLine.c_str()[0] != '['){
        std::string bitsString = "[bits " + std::to_string(targetArch) + "]";
        asmFile << bitsString << "\n";
    }

    asmFile << assembly << "\n" << "hlt" << "\n";
    asmFile.close();
    return true;
}

extern std::string getBytes(std::string fileName){
    std::string outFileName = fileName + ".tmp.out";
    std::string command = "nasm -o " + outFileName + " " + fileName;
    int _ = system(command.c_str());

    std::ifstream as;
    as.open(outFileName, std::ios::binary | std::ios::in);
    as.seekg(0, std::ios::end);
    std::streampos fileSize = as.tellg();
    as.seekg(0, std::ios::beg);

    std::vector<char> buffer(fileSize);
    as.read(buffer.data(), fileSize);

    return hexlify({buffer.data(), buffer.size()});
}
