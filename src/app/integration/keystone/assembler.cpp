#include "assembler.hpp"
ks_engine *ks = nullptr;

std::pair<std::string, std::size_t> assemble(const std::string& assembly, const keystoneSettings& ksSettings) {
    ks_err err;
    size_t size;
    size_t count;
    unsigned char *encode;
    std::pair<std::string, std::size_t> assembled;
    std::cout << assembly << std::endl;
    if (ks == nullptr){
        err = ks_open(ksSettings.arch, ksSettings.mode, &ks);

        if (err != KS_ERR_OK) {
            std::cerr << "ERROR: Failed to initialize Keystone engine: " << ks_strerror(err) << std::endl;
            return {"", 0};
        }

        if (ksSettings.optionType){
            ks_option(ks, ksSettings.optionType, ksSettings.optionValue);
        }
    }

    // Set NASM syntax
    if (ks_asm(ks, assembly.data(), 0, &encode, &size, &count)) {
        std::cerr << "ERROR: " << ks_strerror(ks_errno(ks)) << std::endl;
        ks_close(ks);
        return {"", 0};
    }

    assembled = {std::string((const char*)encode, size), size};

    ks_free(encode);
    ks_close(ks);

    return assembled;
}

std::string getBytes(std::string fileName){
    std::stringstream assembly;
    std::ifstream asmFile(fileName);

    assembly<< asmFile.rdbuf();
    asmFile.close();

    keystoneSettings ksSettings = {.arch = KS_ARCH_X86, .mode = KS_MODE_64, .optionType=KS_OPT_SYNTAX, .optionValue=KS_OPT_SYNTAX_NASM};
    auto bytes = assemble(assembly.str(), ksSettings);

    return hexlify({bytes.first.data(), bytes.second});
}