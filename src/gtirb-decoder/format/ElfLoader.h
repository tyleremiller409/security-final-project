//===- ElfLoader.h ----------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_FORMAT_ELFLOADER_H_
#define SRC_GTIRB_DECODER_FORMAT_ELFLOADER_H_

#include <string>

#include "../CompositeLoader.h"
#include "../Relations.h"
#include "ehp.hpp"

void ElfDynamicEntryLoader(const gtirb::Module &Module, DatalogProgram &Program);

void ElfSymbolLoader(const gtirb::Module &Module, DatalogProgram &Program);

void ElfExceptionLoader(const gtirb::Module &Module, DatalogProgram &Program);

class ElfExceptionDecoder
{
private:
    std::unique_ptr<const EHP::EHFrameParser_t> ehParser;

    souffle::tuple getCIEEntry(souffle::Relation *relation, const EHP::CIEContents_t *cie);
    souffle::tuple getCIEEncoding(souffle::Relation *relation, const EHP::CIEContents_t *cie);
    souffle::tuple getCIEPersonality(souffle::Relation *relation, const EHP::CIEContents_t *cie);
    souffle::tuple getFDE(souffle::Relation *relation, const EHP::FDEContents_t *fde);
    souffle::tuple getFDEPointerLocations(souffle::Relation *relation,
                                          const EHP::FDEContents_t *fde);
    souffle::tuple getEHProgramInstruction(souffle::Relation *relation, uint64_t index,
                                           uint64_t insnAddr,
                                           const EHP::EHProgramInstruction_t *insn,
                                           const EHP::FDEContents_t *fde);
    souffle::tuple getLSDA(souffle::Relation *relation, const EHP::LSDA_t *lsda,
                           const EHP::FDEContents_t *fde);
    souffle::tuple getLSDAPointerLocations(souffle::Relation *relation, const EHP::LSDA_t *lsda,
                                           const EHP::FDEContents_t *fde);
    souffle::tuple getLSDACallSite(souffle::Relation *relation, const EHP::LSDACallSite_t *callSite,
                                   const EHP::LSDA_t *lsda);
    souffle::tuple getLSDATypetableEntry(souffle::Relation *relation, uint64_t index,
                                         const EHP::LSDATypeTableEntry_t *typeEntry,
                                         const EHP::LSDA_t *lsda);

public:
    ElfExceptionDecoder(const gtirb::Module &module);
    void addExceptionInformation(souffle::SouffleProgram *prog);
};

#endif // SRC_GTIRB_DECODER_FORMAT_ELFLOADER_H_
