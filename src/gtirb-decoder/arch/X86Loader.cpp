//===- X86Loader.cpp -------------------------------------------*- C++ -*-===//
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
//  GNU Affero General Public
//  License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "X86Loader.h"

#include <algorithm>
#include <string>
#include <vector>

// #define RLBOX_SINGLE_THREADED_INVOCATIONS
// #include "include/rlbox_noop_sandbox.hpp"
// #include "include/rlbox.hpp"

void X86Loader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.

    rlbox::rlbox_sandbox<rlbox::rlbox_noop_sandbox> sandbox;
    sandbox.create_sandbox();

    auto tainted_bytes = sandbox.malloc_in_sandbox<uint8_t>(Size);
    memcpy(tainted_bytes.unverified_safe_pointer_because(Size, "copying bytes into sandbox"), Bytes, Size);

    auto tainted_csinsn_ptr = sandbox.malloc_in_sandbox<cs_insn*>(1);

    auto tainted_count = sandbox.invoke_sandbox_function(cs_disasm, *CsHandle, tainted_bytes, Size, Addr, 1, tainted_csinsn_ptr);

    // cs_insn* CsInsn;
    // size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    size_t Count = tainted_count.copy_and_verify([](size_t c) {
        if (c == 0 || c == 1) {
            return c;
        }
        exit(1);
    });

    cs_insn UntaintCsInsn;

    auto tainted_csinsn_ptr = tainted_csinsn_ptr_ptr.copy_and_verify([](cs_insn** ptr_ptr) {
        return *ptr_ptr;
    });

    UntaintCsInsn.mnemonic = tainted_csinsn_ptr->mnemonic.copy_and_verify_string([] (std::unique_ptr<char[]> mnemonic) {
        // WRITE: the char buffer inside CsInstruction is CS_MNEMONIC_SIZE long
        // it is also supposed to be ASCII text TODO check if ascii
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

    cs_detail CsDetail;
    UntaintCsInsn.detail = &CsDetail;
    CsDetail.x86.op_count = tainted_csinsn_ptr->detail->op_count.copy_and_verify(
        [](ubyte count) {
            // op_count is used to index an array that is max length of 8
            if (count <= 8) {
                return count;
            }
            exit(1);
    });

    auto verify_reg = [] (x86_reg reg) {
        return 0 <= reg && reg <= 242;
    }

    auto opcode_verifier = [](cs_86_op CsOp) {
        switch(CsOp.type)
        {
            case X86_OP_REG:
                if (!verify_reg(CsOp.reg)) {
                    exit(1);
                };
                break;
            case X86_OP_IMM:
                break;
            case X86_OP_MEM:
                if (!verify_reg(CsOp.mem.base) || !verify_reg(CsOp.mem.scale)) {
                    exit(1);
                }
            case X86_OP_INVALID:
            default:
                exit(1);
                break;
        }

    };

    CsDetail.x86.operands = tainted_csinsn_ptr->detail->op_code.copy_and_verify_range(opcode_verifier, CsDetail.x86.op_count);


    // Build datalog instruction facts from Capstone instruction.
    std::optional<relations::Instruction> Instruction;
    if(Count > 0)
    {
        Instruction = build(Facts, UntaintCsInsn);
    }

    if(Instruction)
    {
        // Add the instruction to the facts table.
        Facts.Instructions.add(*Instruction);
        loadRegisterAccesses(Facts, Addr, UntaintCsInsn);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }

    sandbox.invoke_sandbox_function(cs_free, tainted_csinsn_ptr_ptr.copy_and_verify([](cs_insn** ptr_ptr) { return *ptr_ptr; })), tainted_count);
    // cs_free(CsInsn, Count);
    
    sandbox.free_in_sandbox(tainted_bytes);
    sandbox.free_in_sandbox(tainted_csinsn_ptr);
    sandbox.destroy_sandbox();
}

std::optional<relations::Instruction> X86Loader::build(BinaryFacts& Facts,
                                                       const cs_insn& CsInstruction)
{
    cs_x86& Details = CsInstruction.detail->x86;
    auto [Prefix, Name] = splitMnemonic(CsInstruction);
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            cs_x86_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsOp);
            if(!Op)
            {
                return std::nullopt;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = Facts.Operands.add(*Op);
            OpCodes.push_back(OpIndex);
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    gtirb::Addr Addr(CsInstruction.address);
    uint64_t Size(CsInstruction.size);
    uint8_t Imm(Details.encoding.imm_offset), Disp(Details.encoding.disp_offset);
    return relations::Instruction{Addr, Size, Prefix, Name, OpCodes, Imm, Disp};
}

std::tuple<std::string, std::string> X86Loader::splitMnemonic(const cs_insn& CsInstruction)
{
    std::string PrefixName = uppercase(CsInstruction.mnemonic);
    std::string Prefix, Name;
    size_t Pos = PrefixName.find(' ');
    if(Pos != std::string::npos)
    {
        Prefix = PrefixName.substr(0, Pos);
        Name = PrefixName.substr(Pos + 1);
    }
    else
    {
        Prefix = "";
        Name = PrefixName;
    }
    return {Prefix, Name};
}

std::optional<relations::Operand> X86Loader::build(const cs_x86_op& CsOp)
{
    auto registerName = [this](unsigned int Reg) {
        return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg).copy_and_verify_string([](std::unique_ptr<char[] val) {
            // TODO actually verify later
            return val;
        }));
    };

    switch(CsOp.type)
    {
        case X86_OP_REG:
            return registerName(CsOp.reg);
        case X86_OP_IMM:
            return static_cast<int32_t>(CsOp.imm);
        case X86_OP_MEM:
        {
            relations::IndirectOp I = {
                registerName(CsOp.mem.segment),      registerName(CsOp.mem.base),
                registerName(CsOp.mem.index),        CsOp.mem.scale,
                static_cast<int32_t>(CsOp.mem.disp), static_cast<uint32_t>(CsOp.size) * 8};
            return I;
        }
        case X86_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}
