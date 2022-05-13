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

#define RLBOX_SINGLE_THREADED_INVOCATIONS
#include "rlbox_wasm2c_sandbox.hpp"
#include "rlbox.hpp"

void Arm64Loader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.

    rlbox::rlbox_sandbox<rlbox::rlbox_wasm2c_sandbox> sandbox;
    sandbox.create_sandbox();

    // cs_insn* CsInsn;

    // TODO: COPY THINGS OVER

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

    // memcpy(CsInsn, *(tainted_csinsn_ptr.UNSAFE_unverified()), sizeof(cs_insn));
    
    // size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build datalog instruction facts from Capstone instruction.

    auto tainted_CsInsn_ptr = *tainted_csinsn_ptr_ptr; // I expect this to be tainted<cs_insn *>

    // dereference to go down a level
    auto tainted_detail_ptr = tainted_CsInsn_ptr->detail; // I expect this to be tainted<cs_detail *>

    // cs_detail* detail_ptr = malloc(sizeof(cs_detail));
    // copy and verify out of tainted detail

    // [x] detail-> op count
    // [x] detail -> writeback
    // [x] detail -> operands

    /*
    cs_arm64* arm64_ptr = &(detail_ptr->arm64);
    auto tainted_arm64_ptr = tainted_detail_ptr->arm64;

    arm64_ptr->op_count = tainted_arm64_ptr->op_count.copy_and_verify([](ubyte op_count) {
        // WRITE
        // operands is an array with variable number of elements, 
        // but max length of 8
        if (0 <= op_count && op_count <= 8) {
            return op_count;
        }
        exit(1);
    });

    // writeback is just a boolean, and it depends on the instruction
    arm64->writeback = tainted_arm64_ptr->writeback.copy_and_verify([](boolean wb) { return wb; });
    */

    // cs_arm64_op fields we need to verify:
    /*
            [x] type
            [x] reg, type: arm64_reg (enum)
            [ ] imm - don't think I need to
            [ ] .shift.value - don't think I need to
            [ ] .shift.type - don't think I need to
            [ ] mem.base - don't think I need to
            [ ] mem.index - don't think I need to
            [ ] mem.disp - don't think I need to
            [ ] fp - don't think I need to
            [ ] prefetch - I believe all values for these are safe, because it is passed into a switch case with a default case that is taken care of, but we could use this to demonstrate enum checking
            [ ] barrier - don't think I need to
    */

    /*
    auto op_type_verifier = [] (arm64_op_type type) {
        // WRITE: arm64_op_type is an enum that has non-contiguous
        // values
        switch(type) {
            case ARM64_OP_INVALID: ///< = CS_OP_INVALID (Uninitialized).
            case ARM64_OP_REG:///< = CS_OP_REG (Register operand).
            case ARM64_OP_IMM: ///< = CS_OP_IMM (Immediate operand).
            case ARM64_OP_MEM: ///< = CS_OP_MEM (Memory operand).
            case ARM64_OP_FP: ///< = CS_OP_FP (Floating-Point operand).
            case ARM64_OP_CIMM: ///< C-Immediate
            case ARM64_OP_REG_MRS: ///< MRS register operand.
            case ARM64_OP_REG_MSR: ///< MSR register operand.
            case ARM64_OP_PSTATE: ///< PState operand.
            case ARM64_OP_SYS: ///< SYS operand for IC/DC/AT/TLBI instructions.
            case ARM64_OP_PREFETCH: ///< Prefetch operand (PRFM).
            case ARM64_OP_BARRIER: ///< Memory barrier operand (ISB/DMB/DSB instructions).
                return type;
            default:
                exit(1);
        }
    };

    auto reg_verifier = [] (arm64_reg reg) {
        // WRITE: arm64_reg is an enum that has only 260 values
        if (0 <= reg && reg <= 260) {
            return reg;
        }
        exit(1);
    };



    auto op_verifier = [] (cs_arm64_op CsOp) {
        // TODO may need to put this off or only do portions of it
        // WRITE: type is an enum with non-contiguous values
        switch(CsOp->type) {
            case ARM64_OP_INVALID: ///< = CS_OP_INVALID (Uninitialized).
            case ARM64_OP_REG:///< = CS_OP_REG (Register operand).
            case ARM64_OP_IMM: ///< = CS_OP_IMM (Immediate operand).
            case ARM64_OP_MEM: ///< = CS_OP_MEM (Memory operand).
            case ARM64_OP_FP: ///< = CS_OP_FP (Floating-Point operand).
            case ARM64_OP_CIMM: ///< C-Immediate
            case ARM64_OP_REG_MRS: ///< MRS register operand.
            case ARM64_OP_REG_MSR: ///< MSR register operand.
            case ARM64_OP_PSTATE: ///< PState operand.
            case ARM64_OP_SYS: ///< SYS operand for IC/DC/AT/TLBI instructions.
            case ARM64_OP_PREFETCH: ///< Prefetch operand (PRFM).
            case ARM64_OP_BARRIER: ///< Memory barrier operand (ISB/DMB/DSB instructions).
                break;
            default:
                exit(1);
        }

        // only other value we need to check is the reg field for unions
        // the other values are not exactly easily verifiable (we don't know the assumptions)
        // and only certain op types need regs
        if (0 > CsOp)

        return CsOp;
    };
    arm64_ptr->operands = tainted_arm64_ptr->operands.copy_and_verify_range(op_verifier, arm64_ptr->op_count);
    */


    bool InstAdded = false;
    if(Count > 0)
    {
        // TODO: need to verify but how??
        InstAdded = build(Facts, *tainted_csinsn_ptr_ptr);
    }

    if(InstAdded)
    {
        loadRegisterAccesses(Facts, Addr, *tainted_csinsn_ptr_ptr.);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }
    // how to dereference a tainted pointer?
    sandbox.invoke_sandbox_function(cs_free, *tainted_csinsn_ptr_ptr, Count);
    // free(CsInsn);

    // cs_free(CsInsn, Count);

    // TODO: REMEMBER TO FREE SANDBOX MEMORY VALUES LATER ON
    // - tainted_bytes
    // - tainted_csinsn_ptr??
    sandbox.free_in_sandbox(tainted_bytes);
    sandbox.free_in_sandbox(tainted_csinsn_ptr_ptr);
    sandbox.destroy_sandbox();
}

bool Arm64Loader::build(BinaryFacts& Facts, tainted<const cs_insn&> CsInstruction)
{
    // TODO don't know how to deal with Details rn
    // could make another var called untainted_Details, and then leave Details as is
    // so I remember what's tainted and what's not
    tainted<const cs_arm64&> Details = CsInstruction.detail->arm64;


    auto untainted_mnemonic = CsInstruction.mnemonic.copy_and_verify_string([] (std::unique_ptr<char[]> mnemonic) {
        // WRITE: the char buffer inside CsInstruction is CS_MNEMONIC_SIZE long
        // it is also supposed to be ASCII text TODO check if ascii
        if (std::strlen(mnemonic.get()) > CS_MNEMONIC_SIZE) {
            exit(1);
        }
        return mnemonic;
    });

    std::string Name = uppercase(untainted_mnemonic);
    gtirb::Addr Addr(CsInstruction.address.copy_and_verify([] (ulong addr) {
        return addr;
    }));
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        uint8_t OpCount = Details.op_count.copy_and_verify([] (ubyte op_count) {
            // WRITE: operands is an array with max length of 8, 
            // but it reads OpCount in order to index the array
            if (op_count <= 8) {
                return op_count;
            }
            exit(1);
        });
        for(uint8_t i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            tainted<const cs_arm64_op&> CsOp = Details.operands[i];

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
                switch(CsOp.shift.type.UNSAFE_unverified())
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
                                         static_cast<uint8_t>(CsOp.shift.value.UNSAFE_unverified()), ShiftType});
            }
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    uint64_t Size(CsInstruction.size.UNSAFE_unverified());

    Facts.Instructions.add(relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0});
    if(Details.writeback.UNSAFE_unverified())
    {
        Facts.Instructions.writeback(relations::InstructionWriteback{Addr});
    }
    return true;
}

std::optional<relations::Operand> Arm64Loader::build(tainted<const cs_insn&> CsInsn, uint8_t OpIndex,
                                                     tainted<const cs_arm64_op&> CsOp)
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


    switch(CsOp.type.UNSAFE_unverified())
    {
        case ARM64_OP_REG:
            return RegOp{registerName(CsOp.reg.UNSAFE_unverified())};
        case ARM64_OP_IMM:
            return ImmOp{CsOp.imm.UNSAFE_unverified()};
        case ARM64_OP_MEM:
        {
            int64_t Mult = 1;

            if(CsOp.shift.value != 0)
            {
                // In load and store operations, the only type of shift allowed is LSL.
                if(CsOp.shift.type == ARM64_SFT_LSL)
                {
                    Mult = 1 << CsOp.shift.value.UNSAFE_unverified();
                }
                else
                {
                    std::cerr << "WARNING: unsupported shift in indirect op\n";
                }
            }

            IndirectOp I = {registerName(ARM64_REG_INVALID),
                            registerName(CsOp.mem.base.UNSAFE_unverified()),
                            registerName(CsOp.mem.index.UNSAFE_unverified()),
                            Mult,
                            CsOp.mem.disp.UNSAFE_unverified(),
                            4 * 8};
            return I;
        }
        case ARM64_OP_FP:
            return FPImmOp{CsOp.fp.UNSAFE_unverified()};
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
            if(std::optional<const char*> Label = prefetchValue(CsOp.prefetch.UNSAFE_unverified()))
            {
                return SpecialOp{"prefetch", *Label};
            }
            break;
        }
        case ARM64_OP_BARRIER:
        {
            if(std::optional<const char*> Label = barrierValue(CsOp.barrier.UNSAFE_unverified()))
            {
                return SpecialOp{"barrier", *Label};
            }
            break;
        }
        case ARM64_OP_INVALID:
        default:
            break;
    }
    std::cerr << "WARNING: unhandled operand at " << CsInsn.address.UNSAFE_unverified() << ", op type:" << CsOp.type.UNSAFE_unverified()
              << "\n";
    return std::nullopt;
}

std::optional<std::string> Arm64Loader::operandString(tainted<const cs_insn& CsInsn>, uint8_t Index)
{
    // NOTE: assumes commas occur between operands, and neither commas
    // nor spaces occur within them. This is not true of all operand types
    // (e.g., indirect operands). This method should only be used for
    // instructions where this assumption will hold for all its operands.

    uint8_t CurIndex = 0;
    const char* Start = nullptr;
    size_t Size = 0;

    auto untainted_string = CsInsn.op_str.copy_and_verify_string([] (std::unique_ptr<char[]> val) {
        // TODO actually verify later
        return val;
    });

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
