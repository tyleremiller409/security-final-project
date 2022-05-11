//===- ElfReader.h ----------------------------------------------*- C++ -*-===//
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
#ifndef ELF_GTIRB_BUILDER_H_
#define ELF_GTIRB_BUILDER_H_

#include "./GtirbBuilder.h"

class ElfReaderException : public std::exception
{
    std::string error_message;

public:
    ElfReaderException(const std::string& msg) : error_message(msg)
    {
    }

    virtual const char* what() const throw()
    {
        return error_message.c_str();
    }
};

class ElfReader : public GtirbBuilder
{
public:
    ElfReader(std::string Path, std::string Name, std::shared_ptr<gtirb::Context> Context,
              gtirb::IR* IR, std::shared_ptr<LIEF::Binary> Binary);

protected:
    std::shared_ptr<LIEF::ELF::Binary> Elf;

    void buildSections() override;
    void buildSymbols() override;
    void addEntryBlock() override;
    void addAuxData() override;

    void relocateSections();
    uint64_t tlsBaseAddress();

    std::string getRelocationType(const LIEF::ELF::Relocation& Entry);

private:
    uint64_t TlsBaseAddress = 0;

    // TODO: Handle duplicate section names?
    std::map<std::string, uint64_t> SectionRelocations;

    const std::unordered_set<std::string> Literals = {"pydata", ".ARM.attributes"};
};

#endif // ELF_GTIRB_BUILDER_H_
