//===- Arm64Loader.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "Arm64Loader.h"

#include <algorithm>
#include <string>
#include <vector>


// #define RLBOX_SINGLE_THREADED_INVOCATIONS
// #include "include/rlbox_noop_sandbox.hpp"
// #include "include/rlbox.hpp"

void Arm64Loader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.

    rlbox::rlbox_sandbox<rlbox::rlbox_noop_sandbox> sandbox;
    sandbox.create_sandbox();

    // cs_insn* CsInsn;

    auto tainted_bytes = sandbox.malloc_in_sandbox<uint8_t>(Size);
    memcpy(tainted_bytes.unverified_safe_pointer_because(Size, "copying bytes into sandbox"), Bytes, Size);

    auto tainted_csinsn_ptr_ptr = sandbox.malloc_in_sandbox<cs_insn *>(1);

    auto tainted_count = sandbox.invoke_sandbox_function(cs_disasm, *CsHandle, tainted_bytes, Size, Addr, 1, tainted_csinsn_ptr_ptr);

    size_t Count = tainted_count.copy_and_verify([](size_t c) {
        if (c == 0 || c == 1) {
            return c;
        }
        exit(1);
    });

    cs_insn UntaintCsInsn;

    // get a tainted pointer
    auto tainted_csinsn_ptr = tainted_csinsn_ptr_ptr.copy_and_verify([](cs_insn** ptr_ptr) {
        return *ptr_ptr;
    });


    UntaintCsInsn.mnemonic = tainted_csinsn_ptr->mnemonic.copy_and_verify_string([] 
        (std::unique_ptr<char[]> mnemonic) {
        if (std::strlen(mnemonic.get()) > CS_MNEMONIC_SIZE) {
            exit(1);
        }
        return mnemonic;
    });

    UntaintCsInsn.address = tainted_csinsn_ptr->address.copy_and_verify([] (ulong addr) {
        return addr;
    });
    UntaintCsInsn.size = tainted_csinsn_ptr->size.copy_and_verify([] (ushort sz) {
        return sz;
    });



    UntaintCsInsn.op_str = tainted_csinsn_ptr->op_str.copy_and_verify(
            [] (char[] op_str) {
            for (int i = 0; i < 160; i++) {
                if (op_str[i] == '\0') {
                    return op_str;
                }
            }
            exit(1);
    });


    

    cs_detail CsDetail;
    UntaintCsInsn.detail = &CsDetail;
    CsDetail.arm64.op_count = tainted_csinsn_ptr->detail->op_count.copy_and_verify(
        [](ubyte count) {
            // op_count is used to index an array that is max length of 8
            if (count <= 8) {
                return count;
            }
            exit(1);
    });

    CsDetail.arm64.writeback = tainted_csinsn_ptr->detail->writeback.copy_and_verify(
        [] (bool writeback) {
            return writeback; // this bool does not affect any memory safety in this app
    });

    auto verify_reg = [] (arm64_reg reg) {
        return 0 <= reg && reg <= 260;
    }
    auto operand_verifier = [] (cs_arm64_op CsOp) {
        switch(CsOp.type)
        {
            case ARM64_OP_REG:
                if (!verify_reg(CsOp.reg)) {
                    exit(1);
                }
                break;
            case ARM64_OP_IMM:
                break;
            case ARM64_OP_MEM:
                // need to check mem.base - this is a register
                // mem.index - this is a register
                // mem.disp is an int, so this is fine
                if (!verify_reg(CsOp.mem.index) || !verify_reg(CsOp.mem.base)) {
                    exit(1);
                }
                break;
            case ARM64_OP_FP:
                break;
            case ARM64_OP_CIMM:
                break;
            case ARM64_OP_PSTATE:
                // op_str from cs_insn type has already been verified, nothing
                // to do here
                break;
            case ARM64_OP_REG_MRS:
            case ARM64_OP_REG_MSR:
            case ARM64_OP_SYS:
                // op_str has already been verified, nothing to do here
                break;
            case ARM64_OP_PREFETCH:
                // prefetch value is verified by app later and does not cause memory safety
                // issues, so nothing to check here
                break;
            case ARM64_OP_BARRIER:
                // barrier value is verified by app later and does not cause memory safety
                // issues, so nothing to check here
                break;
            case ARM64_OP_INVALID:
            default:
                exit(1);
        }
        return op;
    }
    CsDetail.arm64.operands = tainted_csinsn_ptr->detail->operands.copy_and_verify_range(
        operand_verifier, CsDetail.arm64.op_count);
    

    
    // size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build datalog instruction facts from Capstone instruction.

    // writeback is just a boolean, and it depends on the instruction

    bool InstAdded = false;
    if(Count > 0)
    {
        // TODO: need to verify but how??
        InstAdded = build(Facts, UntaintCsInsn);
    }

    if(InstAdded)
    {
        loadRegisterAccesses(Facts, Addr, UntaintCsInsn);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }
    // how to dereference a tainted pointer?
    sandbox.invoke_sandbox_function(cs_free, tainted_csinsn_ptr_ptr.copy_and_verify([](cs_insn** ptr_ptr) { return *ptr_ptr; })), Count);
    // free(CsInsn);

    // cs_free(CsInsn, Count);

    sandbox.free_in_sandbox(tainted_bytes);
    sandbox.free_in_sandbox(tainted_csinsn_ptr_ptr);
    sandbox.destroy_sandbox();
}

bool Arm64Loader::build(BinaryFacts& Facts, const cs_insn& CsInstruction)
{

    std::string Name = uppercase(untainted_mnemonic);
    gtirb::Addr Addr(CsInstruction.address.copy_and_verify([] (ulong addr) {
        return addr;
    }));
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        uint8_t OpCount = Details.op_count;
        for(uint8_t i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const cs_arm64_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsInstruction, i, CsOp);
            if(!Op)
            {
                return false;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = Facts.Operands.add(*Op);
            OpCodes.push_back(OpIndex);

            // Populate shift metadata if present.
            if(CsOp.type == ARM64_OP_REG && CsOp.shift.value != 0)
            {
                std::string ShiftType;
                switch(CsOp.shift.type)
                {
                    case ARM64_SFT_LSL:
                        ShiftType = "LSL";
                        break;
                    case ARM64_SFT_MSL:
                        ShiftType = "MSL";
                        break;
                    case ARM64_SFT_LSR:
                        ShiftType = "LSR";
                        break;
                    case ARM64_SFT_ASR:
                        ShiftType = "ASR";
                        break;
                    case ARM64_SFT_ROR:
                        ShiftType = "ROR";
                        break;
                    case ARM64_SFT_INVALID:
                        std::cerr << "WARNING: instruction has a non-zero invalid shift at " << Addr
                                  << "\n";
                        return false;
                }
                Facts.Instructions.shiftedOp(
                    relations::ShiftedOp{Addr, static_cast<uint8_t>(i + 1),
                                         static_cast<uint8_t>(CsOp.shift.value), ShiftType});
            }
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    uint64_t Size(CsInstruction.size);

    Facts.Instructions.add(relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0});
    if(Details.writeback)
    {
        Facts.Instructions.writeback(relations::InstructionWriteback{Addr});
    }
    return true;
}

std::optional<relations::Operand> Arm64Loader::build(const cs_insn& CsInsn, uint8_t OpIndex,
                                                     const cs_arm64_op& CsOp)
{
    using namespace relations;
    // rlbox::rlbox_sandbox<rlbox::rlbox_wasm2c_sandbox> sandbox;
    //sandbox.create_sandbox();

    /*
    auto registerName = [this](unsigned int Reg) {
        // TODO: figure out how to pass struct
        //return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
        auto reg_name = sandbox.invoke_sandbox_function(cs_reg_name, *CsHandle, Reg)
        if(Reg == ARM_REG_INVALID){
            return "NONE"
        } else {
            auto reg_name_ret = uppercase(reg_name.UNSAFE_unverified());
            sandbox.free_in_sandbox(reg_name);
            sandbox.destroy_sandbox()
            return reg_name_ret;
        }
    };
    */

    // original:
    auto registerName = [this](unsigned int Reg) {
        return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg).copy_and_verify_string([](std::unique_ptr<char[] val) {
            // TODO actually verify later
            return val;
        }));
    };


    switch(CsOp.type)
    {
        case ARM64_OP_REG:
            return RegOp{registerName(CsOp.reg)};
        case ARM64_OP_IMM:
            return ImmOp{CsOp.imm};
        case ARM64_OP_MEM:
        {
            int64_t Mult = 1;

            if(CsOp.shift.value != 0)
            {
                // In load and store operations, the only type of shift allowed is LSL.
                if(CsOp.shift.type == ARM64_SFT_LSL)
                {
                    Mult = 1 << CsOp.shift.value;
                }
                else
                {
                    std::cerr << "WARNING: unsupported shift in indirect op\n";
                }
            }

            IndirectOp I = {registerName(ARM64_REG_INVALID),
                            registerName(CsOp.mem.base),
                            registerName(CsOp.mem.index),
                            Mult,
                            CsOp.mem.disp,
                            4 * 8};
            return I;
        }
        case ARM64_OP_FP:
            return FPImmOp{CsOp.fp};
        case ARM64_OP_CIMM:
            std::cerr << "WARNING: unsupported CIMM operand\n";
            break;
        case ARM64_OP_PSTATE:
        {
            std::optional<std::string> OpString = operandString(CsInsn, OpIndex);
            if(OpString )
            {
                return SpecialOp{"pstate", *OpString};
            }
            break;
        }
        case ARM64_OP_REG_MRS:
        case ARM64_OP_REG_MSR:
            // Using capstone 4.x, MRS / MSR instructions produce operand
            // types of the same name, but with capstone 5.x (next / GrammaTech
            // fork), they appear as SYS operands.
            // Fallthrough to SYS so that they are handled the same.
        case ARM64_OP_SYS:
        {
            // It seems like capstone only has a subset of system registers
            // implemented for printing with cs_reg_name, so we have to parse
            // it from the instruction string.
            std::optional<std::string> Reg = operandString(CsInsn, OpIndex);
            if(Reg)
            {
                return RegOp{*Reg};
            }
            break;
        }
        case ARM64_OP_PREFETCH:
        {
            if(std::optional<const char*> Label = prefetchValue(CsOp.prefetch))
            {
                return SpecialOp{"prefetch", *Label};
            }
            break;
        }
        case ARM64_OP_BARRIER:
        {
            if(std::optional<const char*> Label = barrierValue(CsOp.barrier))
            {
                return SpecialOp{"barrier", *Label};
            }
            break;
        }
        case ARM64_OP_INVALID:
        default:
            break;
    }
    std::cerr << "WARNING: unhandled operand at " << CsInsn.address << ", op type:" << CsOp.type
              << "\n";
    return std::nullopt;
}

std::optional<std::string> Arm64Loader::operandString(const cs_insn& CsInsn, uint8_t Index)
{
    // NOTE: assumes commas occur between operands, and neither commas
    // nor spaces occur within them. This is not true of all operand types
    // (e.g., indirect operands). This method should only be used for
    // instructions where this assumption will hold for all its operands.

    uint8_t CurIndex = 0;
    const char* Start = nullptr;
    size_t Size = 0;

    for(const char* Pos = CsInsn.op_str; *Pos != '\0'; Pos++)
    {
        if(*Pos == ',')
        {
            ++CurIndex;
        }
        else if(CurIndex == Index && !isspace(*Pos))
        {
            if(Start == nullptr)
                Start = Pos;

            ++Size;
        }
    }

    if(!Start)
        throw std::logic_error("Operand not found");

    return uppercase(std::string(Start, Size));
}

std::optional<const char*> prefetchValue(const arm64_prefetch_op Op)
{
    switch(Op)
    {
        case ARM64_PRFM_PLDL1KEEP:
            return "pldl1keep";
        case ARM64_PRFM_PLDL1STRM:
            return "pldl1strm";
        case ARM64_PRFM_PLDL2KEEP:
            return "pldl2keep";
        case ARM64_PRFM_PLDL2STRM:
            return "pldl2strm";
        case ARM64_PRFM_PLDL3KEEP:
            return "pldl3keep";
        case ARM64_PRFM_PLDL3STRM:
            return "pldl3strm";
        case ARM64_PRFM_PLIL1KEEP:
            return "plil1keep";
        case ARM64_PRFM_PLIL1STRM:
            return "plil1strm";
        case ARM64_PRFM_PLIL2KEEP:
            return "plil2keep";
        case ARM64_PRFM_PLIL2STRM:
            return "plil2strm";
        case ARM64_PRFM_PLIL3KEEP:
            return "plil3keep";
        case ARM64_PRFM_PLIL3STRM:
            return "plil3strm";
        case ARM64_PRFM_PSTL1KEEP:
            return "pstl1keep";
        case ARM64_PRFM_PSTL1STRM:
            return "pstl1strm";
        case ARM64_PRFM_PSTL2KEEP:
            return "pstl2keep";
        case ARM64_PRFM_PSTL2STRM:
            return "pstl2strm";
        case ARM64_PRFM_PSTL3KEEP:
            return "pstl3keep";
        case ARM64_PRFM_PSTL3STRM:
            return "pstl3strm";
        case ARM64_PRFM_INVALID:
        default:
            break;
    }
    return std::nullopt;
}

std::optional<const char*> barrierValue(const arm64_barrier_op Op)
{
    switch(Op)
    {
        case ARM64_BARRIER_OSHLD:
            return "oshld";
        case ARM64_BARRIER_OSHST:
            return "oshst";
        case ARM64_BARRIER_OSH:
            return "osh";
        case ARM64_BARRIER_NSHLD:
            return "nshld";
        case ARM64_BARRIER_NSHST:
            return "nshst";
        case ARM64_BARRIER_NSH:
            return "nsh";
        case ARM64_BARRIER_ISHLD:
            return "ishld";
        case ARM64_BARRIER_ISHST:
            return "ishst";
        case ARM64_BARRIER_ISH:
            return "ish";
        case ARM64_BARRIER_LD:
            return "ld";
        case ARM64_BARRIER_ST:
            return "st";
        case ARM64_BARRIER_SY:
            return "sy";
        case ARM64_BARRIER_INVALID:
        default:
            break;
    }
    return std::nullopt;
}
