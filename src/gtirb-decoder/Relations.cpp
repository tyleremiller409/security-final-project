//===- Relations.cpp --------------------------------------------*- C++ -*-===//
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
#include "Relations.h"

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const gtirb::Addr& A)
    {
        T << static_cast<uint64_t>(A);
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Relocation& Relocation)
    {
        auto& [Addr, Type, Name, Addend, SymbolIndex, SectionName, RelType] = Relocation;
        T << Addr << Type << Name << Addend << SymbolIndex << SectionName << RelType;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Symbol& Symbol)
    {
        T << Symbol.Addr << Symbol.Size << Symbol.Type << Symbol.Binding << Symbol.Visibility
          << Symbol.SectionIndex << Symbol.OriginTable << Symbol.TableIndex << Symbol.Name;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::DynamicEntry& DynamicEntry)
    {
        T << DynamicEntry.Name << DynamicEntry.Value;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Section& Section)
    {
        T << Section.Name << Section.Size << Section.Addr << Section.Align << Section.Index;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SectionProperty& Property)
    {
        T << Property.Name << Property.Property;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SectionType& Type)
    {
        T << Type.Name << Type.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Instruction& Instruction)
    {
        T << Instruction.Addr << Instruction.Size << Instruction.Prefix << Instruction.Name;
        for(size_t i = 0; i < 4; ++i)
        {
            if(i < Instruction.OpCodes.size())
            {
                T << Instruction.OpCodes[i];
            }
            else
            {
                T << static_cast<uint64_t>(0);
            }
        }
        T << static_cast<uint64_t>(Instruction.ImmediateOffset)
          << static_cast<uint64_t>(Instruction.DisplacementOffset);
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::IndirectOp& Op)
    {
        T << Op.Reg1 << Op.Reg2 << Op.Reg3 << Op.Mult << Op.Disp << Op.Size;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SpecialOp& Op)
    {
        T << Op.Type << Op.Value;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::RegBitFieldOp& R)
    {
        T << R.Op << R.Reg;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::FPImmOp& Op)
    {
        T << Op.Value;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Padding& Block)
    {
        T << Block.Addr << Block.Size;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<gtirb::Addr, gtirb::Addr>& Pair)
    {
        T << std::get<0>(Pair) << std::get<1>(Pair);
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SccIndex& Scc)
    {
        T << Scc.Id << Scc.Index << Scc.Block;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Block& Block)
    {
        T << Block.Addr << Block.Size;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::NextBlock& NextBlock)
    {
        T << NextBlock.Block1 << NextBlock.Block2;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Edge& Edge)
    {
        T << Edge.Source << Edge.Destination << Edge.Conditional << Edge.Indirect << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::TopEdge& Edge)
    {
        T << Edge.Source << Edge.Conditional << Edge.Indirect << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolEdge& Edge)
    {
        T << Edge.Source << Edge.Symbol << Edge.Conditional << Edge.Indirect << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolicExpression& Expr)
    {
        T << Expr.Addr << Expr.Symbol << Expr.Offset;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolMinusSymbol& Expr)
    {
        T << Expr.Addr << Expr.Symbol1 << Expr.Symbol2 << Expr.Offset;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::ShiftedOp& Op)
    {
        T << Op.Addr << static_cast<uint64_t>(Op.Index) << static_cast<uint64_t>(Op.Shift)
          << Op.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::ShiftedWithRegOp& Op)
    {
        T << Op.Addr << static_cast<uint64_t>(Op.Index) << Op.Reg << Op.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::InstructionWriteback& Writeback)
    {
        T << Writeback.Addr;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::RegisterAccess& Access)
    {
        T << Access.Addr << Access.Mode << Access.Register;
        return T;
    }

} // namespace souffle
