
//===- Interpreter.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2021 GrammaTech, Inc.
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

#include <souffle/SouffleInterface.h>

#include <gtirb/gtirb.hpp>

#ifndef GTIRB_SRC_INTERPRETER_H_
#define GTIRB_SRC_INTERPRETER_H_

void runInterpreter(gtirb::IR& IR, gtirb::Module& Module, souffle::SouffleProgram* Program,
                    const std::string& DatalogFile, const std::string& Directory,
                    const std::string& LibDirectory, uint8_t Threads);

#endif // GTIRB_SRC_INTERPRETER_H_
