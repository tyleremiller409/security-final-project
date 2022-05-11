//===- Relations.h ----------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_RELATIONS_H_
#define SRC_GTIRB_DECODER_RELATIONS_H_

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>

#include <gtirb/gtirb.hpp>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "../AuxDataSchema.h"

namespace relations
{
    template <class T>
    struct Data
    {
        gtirb::Addr Addr;
        T Item;
    };

    struct Instruction
    {
        gtirb::Addr Addr;
        uint64_t Size;
        std::string Prefix;
        std::string Name;
        std::vector<uint64_t> OpCodes;
        uint8_t ImmediateOffset;
        uint8_t DisplacementOffset;
    };

    struct FPImmOp
    {
        double Value;
        bool operator<(const FPImmOp& Op) const noexcept
        {
            return Value < Op.Value;
        };
    };

    using ImmOp = int64_t;
    using RegOp = std::string;
    struct IndirectOp
    {
        std::string Reg1;
        std::string Reg2;
        std::string Reg3;
        int64_t Mult;
        int64_t Disp;
        uint64_t Size;

        constexpr bool operator<(const IndirectOp& Op) const noexcept
        {
            return std::tie(Reg1, Reg2, Reg3, Mult, Disp, Size)
                   < std::tie(Op.Reg1, Op.Reg2, Op.Reg3, Op.Mult, Op.Disp, Op.Size);
        };
    };

    struct SpecialOp
    {
        std::string Type;
        std::string Value;

        bool operator<(const SpecialOp& Op) const noexcept
        {
            return std::tie(Type, Value) < std::tie(Op.Type, Op.Value);
        };
    };

    struct RegBitFieldOp
    {
        uint64_t Op;
        std::string Reg;

        constexpr bool operator<(const RegBitFieldOp& A) const noexcept
        {
            return std::tie(Op, Reg) < std::tie(A.Op, A.Reg);
        }
    };
    using RegBitFieldOpVector = std::vector<std::string>;

    using Operand = std::variant<ImmOp, RegOp, RegBitFieldOpVector, IndirectOp, FPImmOp, SpecialOp>;

    using Relocation = auxdata::Relocation;

    struct Symbol
    {
        gtirb::Addr Addr;
        uint64_t Size;
        std::string Type;
        std::string Binding;
        std::string Visibility;
        uint64_t SectionIndex;
        std::string OriginTable;
        uint64_t TableIndex;
        std::string Name;
    };

    struct DynamicEntry
    {
        std::string Name;
        uint64_t Value;
    };

    struct Section
    {
        std::string Name;
        uint64_t Size;
        gtirb::Addr Addr;
        uint64_t Align;
        uint64_t Index;
    };

    struct SectionProperty
    {
        std::string Name;
        std::string Property;
    };

    struct SectionType
    {
        std::string Name;
        uint64_t Type;
    };

    struct Padding
    {
        gtirb::Addr Addr;
        uint64_t Size;
    };

    struct SccIndex
    {
        uint64_t Id;
        int64_t Index;
        gtirb::Addr Block;
    };

    struct Block
    {
        gtirb::Addr Addr;
        uint64_t Size;
    };

    struct NextBlock
    {
        gtirb::Addr Block1;
        gtirb::Addr Block2;
    };

    struct Edge
    {
        gtirb::Addr Source;
        gtirb::Addr Destination;
        std::string Conditional;
        std::string Indirect;
        std::string Type;
    };

    struct TopEdge
    {
        gtirb::Addr Source;
        std::string Conditional;
        std::string Indirect;
        std::string Type;
    };

    struct SymbolEdge
    {
        gtirb::Addr Source;
        std::string Symbol;
        std::string Conditional;
        std::string Indirect;
        std::string Type;
    };

    struct SymbolicExpression
    {
        gtirb::Addr Addr;
        gtirb::Addr Symbol;
        int64_t Offset;
    };

    struct SymbolMinusSymbol
    {
        gtirb::Addr Addr;
        gtirb::Addr Symbol1;
        gtirb::Addr Symbol2;
        int64_t Offset;
    };

    struct ShiftedOp
    {
        gtirb::Addr Addr;
        uint8_t Index;
        uint8_t Shift;
        std::string Type;
    };

    struct ShiftedWithRegOp
    {
        gtirb::Addr Addr;
        uint8_t Index;
        std::string Reg;
        std::string Type;
    };

    struct InstructionWriteback
    {
        gtirb::Addr Addr;
    };

    struct RegisterAccess
    {
        gtirb::Addr Addr;
        std::string Mode;
        std::string Register;
    };

} // namespace relations

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const gtirb::Addr& A);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Relocation& Rel);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Symbol& S);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::DynamicEntry& D);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Section& S);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SectionProperty& S);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SectionType& S);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Instruction& I);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::IndirectOp& I);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SpecialOp& I);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::RegBitFieldOp& R);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::FPImmOp& Op);

    template <class Item>
    souffle::tuple& operator<<(souffle::tuple& T, const relations::Data<Item>& Data)
    {
        T << Data.Addr << static_cast<uint64_t>(Data.Item);
        return T;
    }

    template <class U>
    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<U, uint64_t>& Pair)
    {
        auto& [Element, Id] = Pair;
        T << Id << Element;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Padding& Block);

    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<gtirb::Addr, gtirb::Addr>& Pair);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SccIndex& Scc);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Block& Block);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::NextBlock& NextBlock);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Edge& Edge);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::TopEdge& Edge);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolEdge& Edge);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolicExpression& Expr);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolMinusSymbol& Expr);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::ShiftedOp& Op);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::ShiftedWithRegOp& Op);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::InstructionWriteback& writeback);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::RegisterAccess& RegAccess);

} // namespace souffle

#endif // SRC_GTIRB_DECODER_RELATIONS_H_
