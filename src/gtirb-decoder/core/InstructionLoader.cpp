//===- InstructionLoader.cpp ------------------------------------*- C++ -*-===//
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
#include "InstructionLoader.h"


std::string uppercase(std::string S)
{
    std::transform(S.begin(), S.end(), S.begin(),
                   [](unsigned char C) { return static_cast<unsigned char>(std::toupper(C)); });
    return S;
};

/**
Insert BinaryFacts into the Datalog program.
*/
void InstructionLoader::insert(const BinaryFacts& Facts, DatalogProgram& Program)
{
    auto& [Instructions, Operands] = Facts;
    Program.insert("instruction", Instructions.instructions());
    Program.insert("instruction_writeback", Instructions.writeback());
    Program.insert("invalid_op_code", Instructions.invalid());
    Program.insert("op_shifted", Instructions.shiftedOps());
    Program.insert("op_shifted_w_reg", Instructions.shiftedWithRegOps());
    Program.insert("register_access", Instructions.registerAccesses());
    Program.insert("op_immediate", Operands.imm());
    Program.insert("op_regdirect", Operands.reg());
    Program.insert("op_fp_immediate", Operands.fp_imm());
    Program.insert("op_indirect", Operands.indirect());
    Program.insert("op_special", Operands.special());
    Program.insert("op_register_bitfield", Operands.reg_bitfields());
}

/**
Load register access facts
*/
void InstructionLoader::loadRegisterAccesses(BinaryFacts& Facts, uint64_t Addr,
                                             const cs_insn& CsInstruction)
{

    int MAX_REG_NAME_LEN = 10;

    rlbox::rlbox_sandbox<rlbox::rlbox_noop_sandbox> sandbox;

    sandbox.create_sandbox();

    cs_regs RegsRead, RegsWrite;
    uint8_t RegsReadCount, RegsWriteCount;

    auto tainted_regs_read = sandbox.malloc_in_sandbox<cs_regs>(1);
    auto tainted_regs_read_count = sandbox.malloc_in_sandbox<uint8_t>(1);
    auto tainted_regs_write = sandbox.malloc_in_sandbox<cs_regs>(1);
    auto tainted_regs_write_count = sandbox.malloc_in_sandbox<uint8_t>(1);
    
    auto tainted_cs_insn_ptr = sandbox.malloc_in_sandbox<cs_insn>(1);


    memcpy(tainted_cs_insn_ptr.unverified_safe_pointer_because("copying into sandbox"), &CsInstruction, sizeof(cs_insn));

    if (sandbox.invoke_sandbox_function(cs_regs_access, *CsHandle, tainted_cs_insn_ptr, tainted_regs_read, tainted_regs_read_count, tainted_regs_write, tainted_regs_write_count).copy_and_verify([] (int val) {
        if (val >= 0 && val <= 14) {
            return val;
        }
        exit(1);
    }) != CS_ERR_OK) {
        assert(!"cs_regs_access failed");
    }

    gtirb::Addr GtirbAddr = gtirb::Addr(Addr);

    RegsReadCount = tainted_regs_read_count.copy_and_verify([] (int count) {
        // TODO
        if (count >= 0 && count <= 12) {
            return count;
        }
        exit(1);
    });

    RegsWriteCount = tainted_regs_write_count.copy_and_verify([] (int val) {
        // TODO
        if (count >= 0 && count <= 20) {
            return count;
        }
        exit(1);
    }); 

    for(uint8_t i = 0; i < RegsReadCount; i++)
    {
        Facts.Instructions.registerAccess(relations::RegisterAccess{
            GtirbAddr, "R", uppercase(sandbox.invoke_sandbox_function(cs_reg_name, *CsHandle, RegsRead[i]).copy_and_verify_string([] (std::unique_ptr<char[]> reg_name) {
                if (std::strlen(reg_name.get()) > MAX_REG_NAME_LEN) {
                    exit(1);
                }
                return reg_name;
            }));
    }
    for(uint8_t i = 0; i < RegsWriteCount; i++)
    {
        Facts.Instructions.registerAccess(relations::RegisterAccess{
            GtirbAddr, "W", uppercase(sandbox.invoke_sandbox_function(cs_reg_name, *CsHandle, RegsWrite[i]).copy_and_verify_string([] (std::unique_ptr<char[]> reg_name) {
                if (std::strlen(reg_name.get()) > MAX_REG_NAME_LEN) {
                    exit(1);
                }
                return reg_name;
            }));
    }

    sandbox.free_in_sandbox(tainted_regs_read);
    sandbox.free_in_sandbox(tainted_regs_write);
    sandbox.free_in_sandbox(tainted_regs_read_count);
    sandbox.free_in_sandbox(tainted_regs_write_count);
    sandbox.free_in_sandbox(tainted_cs_insn_ptr);
    sandbox.destroy_sandbox();
}
