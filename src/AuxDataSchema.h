//===- AuxDataSchema.h ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

#ifndef DDISASM_AUXDATASCHEMA_H
#define DDISASM_AUXDATASCHEMA_H

#include <gtirb/gtirb.hpp>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace auxdata
{
    /// ElfDynamicEntry is a tuple of the form {Tag, Value}.
    using ElfDynamicEntry = std::tuple<std::string, uint64_t>;

    /// ElfSymbolInfo is a tuple of the form {Size, Type, Binding, Visibility, SectionIndex}.
    using ElfSymbolInfo = std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>;

    /// ElfSymbolTabIdxInfo is a vector of tuples of the form {Name, Index}.
    using ElfSymbolTabIdxInfo = std::vector<std::tuple<std::string, uint64_t>>;

    /// PeDataDirectory is a tuple of the form {Type, Address, Size}.
    using PeDataDirectory = std::tuple<std::string, uint64_t, uint64_t>;

    /// PeDebugData is a tuple of the form {Type, Address, Size}.
    using PeDebugData = std::tuple<std::string, uint64_t, uint64_t>;

    /// PeExportEntry is a tuple of the form {Address, Ordinal, Name}.
    using PeExportEntry = std::tuple<uint64_t, int64_t, std::string>;

    /// PeImportEntry is a tuple of the form {Iat_address, Ordinal, Function, Library}.
    using PeImportEntry = std::tuple<uint64_t, int64_t, std::string, std::string>;

    /// PeResource is a tuple of the form {Header, Data Length, Data Pointer}.
    using PeResource = std::tuple<std::vector<uint8_t>, gtirb::Offset, uint64_t>;

    /// Relocation is a tuple of the form
    /// {Address, Type, Name, Addend, SymbolIndex, SectionName, RelType}.
    using Relocation =
        std::tuple<uint64_t, std::string, std::string, int64_t, uint64_t, std::string, std::string>;
} // namespace auxdata

/// \file AuxDataSchema.h
/// \ingroup AUXDATA_GROUP
/// \brief AuxData types used by ddisasm that are not sanctioned.
/// \see AUXDATA_GROUP

namespace gtirb
{
    namespace schema
    {
        /// \brief Auxiliary data for extra symbol info.
        struct ElfSymbolInfo
        {
            static constexpr const char* Name = "elfSymbolInfo";
            typedef std::map<gtirb::UUID, auxdata::ElfSymbolInfo> Type;
        };

        /// \brief Auxiliary data for extra symbol info.
        struct ElfSymbolTabIdxInfo
        {
            static constexpr const char* Name = "elfSymbolTabIdxInfo";
            typedef std::map<gtirb::UUID, auxdata::ElfSymbolTabIdxInfo> Type;
        };

        /// \brief Auxiliary data for ELF symbol versions.
        struct ElfSymbolVersions
        {
            static constexpr const char* Name = "elfSymbolVersions";
            typedef std::map<gtirb::UUID, std::string> Type;
        };

        /// \brief Auxiliary data describing a binary's type.
        struct BinaryType
        {
            static constexpr const char* Name = "binaryType";
            typedef std::vector<std::string> Type;
        };

        /// \brief Auxiliary data that maps code blocks to integers
        /// representing strongly connected components in the
        /// intra-procedural CFG. (The CFG without taking into account
        /// call and return edges.)
        struct Sccs
        {
            static constexpr const char* Name = "SCCs";
            typedef std::map<gtirb::UUID, int64_t> Type;
        };

        /// \brief Auxiliary data describing a binary's relocation records.
        struct Relocations
        {
            static constexpr const char* Name = "relocations";
            typedef std::set<auxdata::Relocation> Type;
        };

        /// \brief Auxiliary data describing a binary's dynamic entries.
        struct DynamicEntries
        {
            static constexpr const char* Name = "dynamicEntries";
            typedef std::set<auxdata::ElfDynamicEntry> Type;
        };

        /// \brief Auxiliary data covering data object encoding specifiers.
        struct Encodings
        {
            static constexpr const char* Name = "encodings";
            typedef std::map<gtirb::UUID, std::string> Type;
        };

        /// \brief Auxiliary data mapping a section index to a section UUID.
        struct SectionIndex
        {
            static constexpr const char* Name = "sectionIndex";
            typedef std::map<uint64_t, gtirb::UUID> Type;
        };

        /// \brief Auxiliary data covering ELF section properties.
        struct SectionProperties
        {
            static constexpr const char* Name = "sectionProperties";
            typedef std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Type;
        };

        /// \brief Auxiliary data covering cfi directives.
        struct CfiDirectives
        {
            static constexpr const char* Name = "cfiDirectives";
            typedef std::map<
                gtirb::Offset,
                std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>
                Type;
        };

        /// \brief Auxiliary data that includes names of necessary libraries.
        struct Libraries
        {
            static constexpr const char* Name = "libraries";
            typedef std::vector<std::string> Type;
        };

        /// \brief Auxiliary data that includes names of necessary library paths.
        struct LibraryPaths
        {
            static constexpr const char* Name = "libraryPaths";
            typedef std::vector<std::string> Type;
        };

        /// \brief Auxiliary data that stores the size of symbolic expressions.
        struct SymbolicExpressionSizes
        {
            static constexpr const char* Name = "symbolicExpressionSizes";
            typedef std::map<gtirb::Offset, uint64_t> Type;
        };

        /// \brief Auxiliary data that stores the version of ddisasm used to
        // produce the GTIRB.
        struct DdisasmVersion
        {
            static constexpr const char* Name = "ddisasmVersion";
            typedef std::string Type;
        };

        /// \brief Auxiliary data representing the import table of a PE file.
        struct ImportEntries
        {
            static constexpr const char* Name = "peImportEntries";
            typedef std::vector<auxdata::PeImportEntry> Type;
        };

        /// \brief Auxiliary data representing the export table of a PE file.
        struct ExportEntries
        {
            static constexpr const char* Name = "peExportEntries";
            typedef std::vector<auxdata::PeExportEntry> Type;
        };

        /// \brief Auxiliary data for the UUIDs of imported symbols in a PE file.
        struct PeImportedSymbols
        {
            static constexpr const char* Name = "peImportedSymbols";
            typedef std::vector<gtirb::UUID> Type;
        };

        /// \brief Auxiliary data for the UUIDs of exported symbols in a PE file.
        struct PeExportedSymbols
        {
            static constexpr const char* Name = "peExportedSymbols";
            typedef std::vector<gtirb::UUID> Type;
        };

        // \brief Auxiliary data for PE resources.
        struct PeResources
        {
            static constexpr const char* Name = "peResources";
            typedef std::vector<auxdata::PeResource> Type;
        };

        /// \brief Auxiliary data representing the data directory entries of a PE file.
        struct PeDataDirectories
        {
            static constexpr const char* Name = "peDataDirectories";
            typedef std::vector<auxdata::PeDataDirectory> Type;
        };

        /// \brief Auxiliary data listing of debug data boundaries in a PE image.
        struct PeDebugData
        {
            static constexpr const char* Name = "peDebugData";
            typedef std::vector<auxdata::PeDebugData> Type;
        };

        /// \brief Auxiliary data for Souffle fact files.
        struct SouffleFacts
        {
            static constexpr const char* Name = "souffleFacts";
            // Entries of the form {Name, {TypeSignature, CSV}}.
            typedef std::map<std::string, std::tuple<std::string, std::string>> Type;
        };

        /// \brief Auxiliary data for Souffle output files.
        struct SouffleOutputs
        {
            static constexpr const char* Name = "souffleOutputs";
            // Entries of the form {Name, {TypeSignature, CSV}}.
            typedef std::map<std::string, std::tuple<std::string, std::string>> Type;
        };

        /// \brief Auxiliary data for the list of possible entry points in a raw binary.
        struct RawEntries
        {
            static constexpr const char* Name = "rawEntries";
            typedef std::vector<uint64_t> Type;
        };

    } // namespace schema
} // namespace gtirb

#endif // DDISASM_AUXDATASCHEMA_H
