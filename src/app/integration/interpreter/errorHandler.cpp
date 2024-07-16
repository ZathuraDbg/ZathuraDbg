#include "errorHandler.hpp"

void handleUCErrors(uc_err err){
    if (err == UC_ERR_INSN_INVALID){
        LOG_ERROR("Failed on uc_emu_start(): Invalid Instruction provided.");
        tinyfd_messageBox("ERROR!", "Invalid instruction found in the provided code!!", "ok", "error", 0);
    }
    else if (err < UC_ERR_VERSION){
        LOG_ERROR("Failed on uc_emu_start() with error returned " <<  err << ": " << uc_strerror(err));
        tinyfd_messageBox("INTERNAL ERROR!", "Failed to run the code because the internal configuration"
                                             " has some issues. Please report this on GitHub with your logs!", "ok", "error", 0);
    }
    else if (err > UC_ERR_VERSION && err < UC_ERR_HOOK){
        LOG_ERROR("Unmapped Memory Access Error!");

        if (err == UC_ERR_READ_UNMAPPED){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to read from memory which is not mapped.");
            tinyfd_messageBox("Memory Access Error!", "Attempt to read from memory location which is not mapped!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_WRITE_UNMAPPED){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to write to memory which is not mapped.");
            tinyfd_messageBox("Memory Access Error!", "Attempt to write to memory location which is not mapped!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_FETCH_UNMAPPED){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to fetch from memory which is not mapped.");
            tinyfd_messageBox("Memory Access Error!", "Attempt to fetch from memory location which is not mapped!!", "ok", "error", 0);
        }
    }
    else if (err > UC_ERR_MAP && err < UC_ERR_ARG){
        // MEMORY PROTECTION ERRORS
        LOG_ERROR("Memory Protection Error!");

        if (err == UC_ERR_WRITE_PROT){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to write to memory which does not have write permission enabled.");
            tinyfd_messageBox("Memory Protection Error!", "Attempt to write to memory location which does not have"
                                                          " write permission enabled!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_READ_PROT){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to read memory which does not have read permission enabled.");
            tinyfd_messageBox("Memory Protection Error!", "Attempt to write to memory location which does not have write"
                                                          " permission enabled!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_FETCH_PROT){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to fetch memory which does not have fetch permission enabled.");
            tinyfd_messageBox("Memory Protection Error!", "Attempt to write to memory location which does not have fetch"
                                                          " permission enabled!!", "ok", "error", 0);
        }
    }
    else if ((err > UC_ERR_ARG) && (err < UC_ERR_HOOK_EXIST)){
        // Unaligned error
        LOG_ERROR("Unaligned Memory Access Error!");
        if (err == UC_ERR_READ_UNALIGNED){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to read data from memory at an address that is not properly "
                      "aligned for the data type being accessed");
            tinyfd_messageBox("Unaligned Memory Access Error!", "Attempt to read data from memory at an address that is not properly "
                                                                "aligned for the data type being accessed", "ok", "error", 0);
        }
        else if (err == UC_ERR_WRITE_UNALIGNED){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to write data to memory at an address that is not properly "
                      "aligned for the data type being accessed");
            tinyfd_messageBox("Unaligned Memory Access Error!", "Attempt to write data to memory at an address that is not properly "
                                                                "aligned for the data type being accessed", "ok", "error", 0);
        }
        else if (err == UC_ERR_FETCH_UNALIGNED){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to fetch data from memory at an address that is not properly "
                      "aligned for the data type being accessed");
            tinyfd_messageBox("Unaligned Memory Access Error!", "Attempt to fetch data from memory at an address that is not properly "
                                                                "aligned for the data type being accessed", "ok", "error", 0);
        }
    }
    else if (err == UC_ERR_MAP){
        LOG_ERROR("Failed on uc_emu_start(): Attempt to access memory that is not mapped.");
        tinyfd_messageBox("Memory Access Error!", "Attempt to access memory that is not mapped.", "ok", "error", 0);
    }
    else if (err == UC_ERR_EXCEPTION){
        LOG_ERROR("Failed on uc_emu_start(): Exception occurred during emulation.");
        tinyfd_messageBox("Exception Error!", "Exception occurred during emulation which is not manually handled.", "ok", "error", 0);
    }
}
