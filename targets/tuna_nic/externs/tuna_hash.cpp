/* Copyright 2021 SYRMIA LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Dusan Krdzic (dusan.krdzic@syrmia.com)
 *
 */

#include "tuna_hash.h"

namespace {

bm::ByteContainer
build_buffer(const std::vector<bm::Field> &fields) {
  int nbits = 0;
  int nbytes;
  for (const auto &field : fields) {
    nbits += field.get_nbits();
  }
  nbytes = (nbits + 7) / 8;
  bm::ByteContainer buf(nbytes, '\x00');
  nbits = (nbytes * 8 - nbits);  // pad to the left with 0s
  for (const auto &field : fields) {
    char *ptr = buf.data() + (nbits / 8);
    field.deparse(ptr, nbits % 8);
    nbits += field.get_nbits();
  }
  return buf;
}

}  // namespace

namespace bm {

namespace tuna {

void
TUNA_Hash::init() {
  if (algorithm == "crc32" || algorithm == "crc32_1edc6f41") algorithm = "crc32_custom";
  calc = CalculationsMap::get_instance()->get_copy(algorithm);

  if (!calc) return;
  if (algorithm == "toeplitz") {
    static const unsigned char raw_key[] = {
      0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
      0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
      0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
      0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
      0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    };
    const ToeplitzMgr::key_t default_key(
      reinterpret_cast<const char *>(raw_key), sizeof(raw_key));
    ToeplitzMgr::update_key(calc.get(), default_key);
  } else if (algorithm == "crc32_custom") {
    CustomCrcMgr<uint32_t>::update_config(calc.get(),
      {polynomial.get_uint(), 0xffffffff, 0xffffffff, true, true});
  }
}

void
TUNA_Hash::get_hash(Field &dst, const std::vector<Field> &fields) {
  auto buf = build_buffer(fields);
  auto hash = compute(buf.data(), buf.size());
  dst.set(hash);
}

void
TUNA_Hash::get_hash_mod(Field &dst, const Data &base, const std::vector<Field> &fields, const Data &max) {
  auto buf = build_buffer(fields);
  auto hash = compute(buf.data(), buf.size());
  auto result = base.get<uint64_t>() + (hash % max.get<uint64_t>());
  dst.set(result);
}

uint64_t
TUNA_Hash::compute(const char *buf, size_t s) {
  return calc.get()->output(buf, s);
}

BM_REGISTER_EXTERN_W_NAME(Hash, TUNA_Hash);
BM_REGISTER_EXTERN_W_NAME_METHOD(Hash, TUNA_Hash, get_hash, Field &, const std::vector<Field>);
BM_REGISTER_EXTERN_W_NAME_METHOD(Hash, TUNA_Hash, get_hash_mod, Field &, const Data &, const std::vector<Field>, const Data &);

}  // namespace bm::tuna

}  // namespace bm

int import_hash() {
  return 0;
}
