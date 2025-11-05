/* Copyright 2013-present Barefoot Networks, Inc.
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
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

/* NIC instance */

#include <bm/TunaNic.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

#include "tuna_nic.h"

namespace {
bm::tuna::TunaNic *tuna_nic;
bm::TargetParserBasic *tuna_nic_parser;
}  // namespace

namespace tunanic_runtime {
shared_ptr<TunaNicIf> get_handler(bm::tuna::TunaNic *sw);
}  // namespace tunanic_runtime

int
main(int argc, char* argv[]) {
  using bm::tuna::TunaNic;
  tuna_nic = new TunaNic();
  tuna_nic_parser = new bm::TargetParserBasic();
  tuna_nic_parser->add_flag_option("enable-swap",
                                        "enable JSON swapping at runtime");
  int status = tuna_nic->init_from_command_line_options(
      argc, argv, tuna_nic_parser);
  if (status != 0) std::exit(status);

  bool enable_swap_flag = false;
  if (tuna_nic_parser->get_flag_option("enable-swap", &enable_swap_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS)
    std::exit(1);
  if (enable_swap_flag) tuna_nic->enable_config_swap();

  int thrift_port = tuna_nic->get_runtime_port();
  bm_runtime::start_server(tuna_nic, thrift_port);
  using ::tunanic_runtime::TunaNicIf;
  using ::tunanic_runtime::TunaNicProcessor;
  bm_runtime::add_service<TunaNicIf, TunaNicProcessor>(
      "tuna_nic", tunanic_runtime::get_handler(tuna_nic));
  tuna_nic->start_and_return();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
