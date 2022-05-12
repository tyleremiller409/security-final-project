//===- X64Loader.cpp -------------------------------------------*- C++ -*-===//
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
#include "X64Loader.h"

#include <algorithm>
#include <string>
#include <vector>

void X64Loader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.

    rlbox::rlbox_sandbox<rlbox::rlbox_wasm2c_sandbox> sandbox;
    sandbox.create_sandbox();

    auto tainted_bytes = sandbox.malloc_in_sandbox<uint8_t>(Size);
    memcpy(tainted_bytes.unverified_safe_pointer_because(Size, "copying bytes into sandbox"), Bytes, Size);

    auto tainted_csinsn_ptr = sandbox.malloc_in_sandbox<uint64_t>(1);

    size_t tainted_count = sandbox.invoke_sandbox_function(__, tainted_bytes, Size, Addr, 1, tainted_csinsn_ptr);

    // cs_insn* CsInsn;
    // size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build datalog instruction facts from Capstone instruction.
    std::optional<relations::Instruction> Instruction;
    if(Count > 0)
    {
        Instruction = build(Facts, *(tainted_csinsn_ptr.UNSAFE_unverified()));
    }

    if(Instruction)
    {
        // Add the instruction to the facts table.
        Facts.Instructions.add(*Instruction);
        loadRegisterAccesses(Facts, Addr, *(tainted_csinsn_ptr.UNSAFE_unverified()));
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }

    // cs_free(CsInsn, Count);
    sandbox.invoke_sandbox_function(cs_free, *tainted_csinsn_ptr, tainted_count);
    // free(CsInsn);

    sandbox.free_in_sandbox(tainted_bytes)
    sandbox.free_in_sandbox(tainted_csinsn_ptr)
    sandbox.destroy_sandbox();

}

std::optional<relations::Instruction> X64Loader::build(BinaryFacts& Facts,
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

std::tuple<std::string, std::string> X64Loader::splitMnemonic(const cs_insn& CsInstruction)
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

std::optional<relations::Operand> X64Loader::build(const cs_x86_op& CsOp)
{
    auto registerName = [this](unsigned int Reg) {
        // TODO: figure out how to pass struct
        //return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
        auto reg_name = sandbox.invoke_sandbox_function(cs_reg_name, __, Reg)
        if(Reg == ARM_REG_INVALID){
            return "NONE"
        } else {
            auto reg_name_ret = uppercase(reg_name.UNSAFE_unverified());
            sandbox.free_in_sandbox(reg_name);
            sandbox.destroy_sandbox()
            return reg_name_ret;
        }
    };

    switch(CsOp.type)
    {
        case X86_OP_REG:
            return registerName(CsOp.reg);
        case X86_OP_IMM:
            return CsOp.imm;
        case X86_OP_MEM:
        {
            relations::IndirectOp I = {registerName(CsOp.mem.segment),
                                       registerName(CsOp.mem.base),
                                       registerName(CsOp.mem.index),
                                       CsOp.mem.scale,
                                       CsOp.mem.disp,
                                       static_cast<uint64_t>(CsOp.size) * 8};
            return I;
        }
        case X86_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}
