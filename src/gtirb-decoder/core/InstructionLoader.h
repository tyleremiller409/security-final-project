//===- InstructionLoader.h --------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_
#define SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_
#include <capstone/capstone.h>

#include <gtirb/gtirb.hpp>
#include <vector>

#include "../DatalogProgram.h"
#include "../Relations.h"


#define RLBOX_SINGLE_THREADED_INVOCATIONS
#define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol
#include "include/rlbox_noop_sandbox.hpp"
#include "include/rlbox.hpp"

class OperandFacts
{
public:
    uint64_t add(const relations::Operand& Op)
    {
        return std::visit(*this, Op);
    }

    uint64_t operator()(const relations::ImmOp& Op)
    {
        return index(Imm, Op);
    }

    uint64_t operator()(const relations::RegOp& Op)
    {
        return index(Reg, Op);
    }

    uint64_t operator()(const std::vector<std::string>& Op)
    {
        return index(RegBitFields, Op);
    }

    uint64_t operator()(const relations::FPImmOp& Op)
    {
        return index(FPImm, Op);
    }

    uint64_t operator()(const relations::IndirectOp& Op)
    {
        return index(Indirect, Op);
    }

    uint64_t operator()(const relations::SpecialOp& Op)
    {
        return index(Special, Op);
    }

    const std::map<relations::ImmOp, uint64_t>& imm() const
    {
        return Imm;
    }

    const std::map<relations::RegOp, uint64_t>& reg() const
    {
        return Reg;
    }

    const std::vector<relations::RegBitFieldOp> reg_bitfields() const
    {
        std::vector<relations::RegBitFieldOp> RegBitFieldsForSouffle;
        for(auto It = RegBitFields.begin(); It != RegBitFields.end(); ++It)
        {
            auto Regs = It->first;
            auto Index = It->second;
            for(auto It2 = Regs.begin(); It2 != Regs.end(); ++It2)
            {
                auto K = relations::RegBitFieldOp{Index, *It2};
                RegBitFieldsForSouffle.push_back(K);
            }
        }
        return RegBitFieldsForSouffle;
    }

    const std::map<relations::FPImmOp, uint64_t>& fp_imm() const
    {
        return FPImm;
    }

    const std::map<relations::IndirectOp, uint64_t>& indirect() const
    {
        return Indirect;
    }

    const std::map<relations::SpecialOp, uint64_t>& special() const
    {
        return Special;
    }

protected:
    template <typename T>
    uint64_t index(std::map<T, uint64_t>& OpTable, const T& Op)
    {
        auto [Iter, Inserted] = OpTable.try_emplace(Op, Index);
        if(Inserted)
        {
            Index++;
        }
        return Iter->second;
    }

private:
    // We reserve 0 for empty operators.
    uint64_t Index = 1;

    std::map<relations::ImmOp, uint64_t> Imm;
    std::map<relations::RegOp, uint64_t> Reg;
    std::map<std::vector<std::string>, uint64_t> RegBitFields;
    std::map<relations::FPImmOp, uint64_t> FPImm;
    std::map<relations::IndirectOp, uint64_t> Indirect;
    std::map<relations::SpecialOp, uint64_t> Special;
};

class InstructionFacts
{
public:
    void add(const relations::Instruction& I)
    {
        Instructions.push_back(I);
    }

    void invalid(gtirb::Addr A)
    {
        InvalidInstructions.push_back(A);
    }

    void shiftedOp(const relations::ShiftedOp& Op)
    {
        ShiftedOps.push_back(Op);
    }

    void shiftedWithRegOp(const relations::ShiftedWithRegOp& Op)
    {
        ShiftedWithRegOps.push_back(Op);
    }

    const std::vector<relations::Instruction>& instructions() const
    {
        return Instructions;
    }

    const std::vector<gtirb::Addr>& invalid() const
    {
        return InvalidInstructions;
    }

    const std::vector<relations::ShiftedOp>& shiftedOps() const
    {
        return ShiftedOps;
    }

    const std::vector<relations::ShiftedWithRegOp>& shiftedWithRegOps() const
    {
        return ShiftedWithRegOps;
    }

    void writeback(const relations::InstructionWriteback& writeback)
    {
        InstructionWritebackList.push_back(writeback);
    }

    const std::vector<relations::InstructionWriteback>& writeback() const
    {
        return InstructionWritebackList;
    }

    void registerAccess(const relations::RegisterAccess& access)
    {
        RegisterAccesses.push_back(access);
    }

    const std::vector<relations::RegisterAccess>& registerAccesses() const
    {
        return RegisterAccesses;
    }

private:
    std::vector<relations::Instruction> Instructions;
    std::vector<gtirb::Addr> InvalidInstructions;
    std::vector<relations::ShiftedOp> ShiftedOps;
    std::vector<relations::ShiftedWithRegOp> ShiftedWithRegOps;
    std::vector<relations::InstructionWriteback> InstructionWritebackList;
    std::vector<relations::RegisterAccess> RegisterAccesses;
};

struct BinaryFacts
{
    InstructionFacts Instructions;
    OperandFacts Operands;
};

class InstructionLoader
{
public:
    virtual ~InstructionLoader(){};

    void operator()(const gtirb::Module& Module, DatalogProgram& Program)
    {
        BinaryFacts Facts;
        load(Module, Facts);
        insert(Facts, Program);
    }

protected:
    explicit InstructionLoader(uint8_t N) : InstructionSize{N}
    {

        rlbox::rlbox_sandbox<rlbox::rlbox_noop_sandbox> sandbox;

        sandbox.create_sandbox();

        // Create smart Capstone handle.
        CsHandle.reset(new csh(0), [](csh* Handle) {
            auto Err = sandbox.invoke_sandbox_function(cs_close, Handle);
            // cs_close(Handle);
            assert(Err.copy_and_verify([] (int val) {
                if (val >= 0 && val <= 14) {
                    return val;
                }
                exit(1);
            }) == CS_ERR_OK && "Failed to shutdown the capstone engine.");
            delete Handle;
        });

        sandbox.destroy_sandbox();
    };

    virtual void insert(const BinaryFacts& Facts, DatalogProgram& Program);

    virtual void load(const gtirb::Module& Module, BinaryFacts& Facts)
    {
        for(const auto& Section : Module.sections())
        {
            bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
            if(Executable)
            {
                for(const auto& ByteInterval : Section.byte_intervals())
                {
                    load(Module, ByteInterval, Facts);
                }
            }
        }
    }

    // NOTE: If needed, Module can be used in the inherited functions:
    // e.g., ARM32
    virtual void load([[maybe_unused]] const gtirb::Module& Module,
                      const gtirb::ByteInterval& ByteInterval, BinaryFacts& Facts)
    {
        assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

        uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
        uint64_t Size = ByteInterval.getInitializedSize();
        auto Data = ByteInterval.rawBytes<const uint8_t>();

        while(Size > 0)
        {
            decode(Facts, Data, Size, Addr);
            Addr += InstructionSize;
            Data += InstructionSize;
            Size -= InstructionSize;
        }
    }

    // Load register accesses for a cs_insn
    virtual void loadRegisterAccesses(BinaryFacts& Facts, uint64_t Addr,
                                      const cs_insn& CsInstruction);

    // Disassemble bytes and build Instruction and Operand facts.
    virtual void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) = 0;

    // We default to decoding instructions at every byte offset.
    uint8_t InstructionSize = 1;

    std::shared_ptr<csh> CsHandle;
};

// Decorator for loading instructions from known code blocks.
template <typename T>
class CodeBlockLoader : public T
{
protected:
    void load(const gtirb::Module& Module, BinaryFacts& Facts) override
    {
        for(auto& Block : Module.code_blocks())
        {
            load(Block, Facts);
        }
    }

    void load(const gtirb::CodeBlock& Block, BinaryFacts& Facts)
    {
        assert(Block.getAddress() && "Found code block without address.");
        gtirb::Addr Addr = *Block.getAddress();

        const gtirb::ByteInterval* ByteInterval = Block.getByteInterval();
        assert(ByteInterval->getAddress() && "Found byte interval without address.");

        assert(Addr < (*ByteInterval->getAddress() + ByteInterval->getInitializedSize())
               && "Found uninitialized code block.");
        auto Data = ByteInterval->rawBytes<const uint8_t>() + Block.getOffset();
        uint64_t Size = ByteInterval->getInitializedSize() - Block.getOffset();

        // TODO: Add `InstructionLimit` parameter for decoding a number of
        //       instructions from the beginning of the code block.
        T::decode(Facts, Data, Size, static_cast<uint64_t>(Addr));
    }
};

std::string uppercase(std::string S);

#endif // SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_
