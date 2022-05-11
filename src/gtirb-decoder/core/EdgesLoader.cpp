//===- EdgesLoader.cpp ------------------------------------------*- C++ -*-===//
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
#include "EdgesLoader.h"

#include "../../AuxDataSchema.h"

void BlocksLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::Block> Blocks;
    std::vector<relations::NextBlock> NextBlocks;

    if(Module.code_blocks().empty())
    {
        return;
    }

    std::optional<gtirb::Addr> PrevBlockAddr = Module.code_blocks().begin()->getAddress();

    for(auto& Block : Module.code_blocks())
    {
        uint64_t BlockSize = Block.getSize();
        std::optional<gtirb::Addr> BlockAddr = Block.getAddress();
        assert(BlockAddr && PrevBlockAddr && "Found code block without address.");

        Blocks.push_back({*BlockAddr, BlockSize});
        if(*PrevBlockAddr < *BlockAddr)
        {
            NextBlocks.push_back({*PrevBlockAddr, *BlockAddr});
        }
        PrevBlockAddr = BlockAddr;
    }

    Program.insert("block", std::move(Blocks));
    Program.insert("next_block", std::move(NextBlocks));
}

std::tuple<std::string, std::string, std::string> edgeProperties(const gtirb::EdgeLabel& Label)
{
    assert(Label.has_value() && "Found edge without a label");

    std::string Conditional = "false";
    if(std::get<gtirb::ConditionalEdge>(*Label) == gtirb::ConditionalEdge::OnTrue)
    {
        Conditional = "true";
    }

    std::string Indirect = "false";
    if(std::get<gtirb::DirectEdge>(*Label) == gtirb::DirectEdge::IsIndirect)
    {
        Indirect = "true";
    }

    std::string Type;
    switch(std::get<gtirb::EdgeType>(*Label))
    {
        case gtirb::EdgeType::Branch:
            Type = "branch";
            break;
        case gtirb::EdgeType::Call:
            Type = "call";
            break;
        case gtirb::EdgeType::Fallthrough:
            Type = "fallthrough";
            break;
        case gtirb::EdgeType::Return:
            Type = "return";
            break;
        case gtirb::EdgeType::Syscall:
            Type = "syscall";
            break;
        case gtirb::EdgeType::Sysret:
            Type = "sysret";
            break;
    }

    return {Conditional, Indirect, Type};
}

void CfgLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::Edge> Edges;
    std::vector<relations::TopEdge> TopEdges;
    std::vector<relations::SymbolEdge> SymbolEdges;

    std::map<const gtirb::ProxyBlock*, std::string> InvSymbolMap;
    for(auto& Symbol : Module.symbols())
    {
        if(const gtirb::ProxyBlock* Proxy = Symbol.getReferent<gtirb::ProxyBlock>())
        {
            InvSymbolMap[Proxy] = Symbol.getName();
        }
    }

    const gtirb::CFG& Cfg = Module.getIR()->getCFG();
    auto [EdgesBegin, EdgesEnd] = boost::edges(Cfg);
    for(const auto& Edge : boost::make_iterator_range(EdgesBegin, EdgesEnd))
    {
        auto Source = boost::source(Edge, Cfg);
        auto Target = boost::target(Edge, Cfg);
        if(const gtirb::CodeBlock* Src = dyn_cast<gtirb::CodeBlock>(Cfg[Source]))
        {
            std::optional<gtirb::Addr> SrcAddr = Src->getAddress();
            assert(SrcAddr && "Found source block without address.");

            const gtirb::EdgeLabel& Label = Cfg[Edge];
            auto [Conditional, Indirect, Type] = edgeProperties(Label);

            if(const gtirb::CodeBlock* Dest = dyn_cast<gtirb::CodeBlock>(Cfg[Target]))
            {
                std::optional<gtirb::Addr> DestAddr = Dest->getAddress();
                assert(DestAddr && "Found destination block without address.");
                Edges.push_back({*SrcAddr, *DestAddr, Conditional, Indirect, Type});
            }

            if(const gtirb::ProxyBlock* Dest = dyn_cast<gtirb::ProxyBlock>(Cfg[Target]))
            {
                auto It = InvSymbolMap.find(Dest);
                if(It != InvSymbolMap.end())
                {
                    std::string Symbol = It->second;
                    SymbolEdges.push_back({*SrcAddr, Symbol, Conditional, Indirect, Type});
                }
                else
                {
                    TopEdges.push_back({*SrcAddr, Conditional, Indirect, Type});
                }
            }
        }
    }

    Program.insert("cfg_edge", std::move(Edges));
    Program.insert("cfg_edge_to_top", std::move(TopEdges));
    Program.insert("cfg_edge_to_symbol", std::move(SymbolEdges));
}
