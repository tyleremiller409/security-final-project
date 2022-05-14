//===- X86Loader.h ----------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_X86DECODER_H_
#define SRC_GTIRB_DECODER_ARCH_X86DECODER_H_

#include <capstone/capstone.h>

#include <optional>
#include <string>
#include <tuple>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

class X86Loader : public InstructionLoader
{
public:
    X86Loader() : InstructionLoader{1}
    {
        // Setup Capstone engine.

        rlbox::rlbox_sandbox<rlbox::rlbox_noop_sandbox> sandbox;

        sandbox.create_sandbox();

        // [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_X86, CS_MODE_32, CsHandle.get());

        auto Err = sandbox.invoke_sandbox_function(cs_open, CS_ARCH_X86, CS_MODE_32, CsHandle.get());

        assert(Err.copy_and_verify([] (int val) {
            if (val >= 0 && val <= 14) {
                return val;
            }
            exit(1);
        }) == CS_ERR_OK && "Failed to initialize X86 disassembler.");
        
        
        // cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);

        sandbox.invoke_sandbox_function(cs_option, *CsHandle, CS_OPT_DETAIL, CS_OPT_ON);

        sandbox.destroy_sandbox();
    }

protected:
    void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;

private:
    std::optional<relations::Operand> build(const cs_x86_op& CsOp);
    std::optional<relations::Instruction> build(BinaryFacts& Facts, const cs_insn& CsInstruction);
    std::tuple<std::string, std::string> splitMnemonic(const cs_insn& CsInstruction);
};

#endif // SRC_GTIRB_DECODER_ARCH_X86DECODER_H_
