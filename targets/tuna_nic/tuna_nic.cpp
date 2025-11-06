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

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>

#include "tuna_nic.h"

namespace {

struct hash_ex {
  uint32_t operator()(const char *buf, size_t s) const {
    const uint32_t p = 16777619;
    uint32_t hash = 2166136261;

    for (size_t i = 0; i < s; i++)
      hash = (hash ^ buf[i]) * p;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;
    return static_cast<uint32_t>(hash);
  }
};

struct bmv2_hash {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::xxh64(buf, s);
  }
};

}  // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

extern int import_primitives();
extern int import_counters();
extern int import_meters();
extern int import_random();
extern int import_internet_checksum();
extern int import_hash();

namespace bm {

namespace tuna {

static constexpr uint16_t MAX_MIRROR_SESSION_ID = (1u << 15) - 1;
packet_id_t TunaNic::packet_id = 0;

class TunaNic::MirroringSessions {
 public:
  bool add_session(mirror_id_t mirror_id,
                   const MirroringSessionConfig &config) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= MAX_MIRROR_SESSION_ID) {
      sessions_map[mirror_id] = config;
      return true;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session added.");
      return false;
    }
  }

  bool delete_session(mirror_id_t mirror_id) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= MAX_MIRROR_SESSION_ID) {
      return sessions_map.erase(mirror_id) == 1;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session deleted.");
      return false;
    }
  }

  bool get_session(mirror_id_t mirror_id,
                   MirroringSessionConfig *config) const {
    Lock lock(mutex);
    auto it = sessions_map.find(mirror_id);
    if (it == sessions_map.end()) return false;
    *config = it->second;
    return true;
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  mutable std::mutex mutex;
  std::unordered_map<mirror_id_t, MirroringSessionConfig> sessions_map;
};

TunaNic::TunaNic(bool enable_swap)
  : Switch(enable_swap),
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    ingress_buffer(nb_ingress_threads,
                   buffer_capacity, IngressThreadMapper(nb_ingress_threads),
                   SSWITCH_PRIORITY_QUEUEING_NB_QUEUES),
    egress_buffer(nb_egress_threads,
                   buffer_capacity, EgressThreadMapper(nb_egress_threads),
                   SSWITCH_PRIORITY_QUEUEING_NB_QUEUES),
#else
    ingress_buffer(nb_ingress_threads,
                   buffer_capacity, IngressThreadMapper(nb_ingress_threads)),
    egress_buffer(nb_egress_threads,
                   buffer_capacity, EgressThreadMapper(nb_egress_threads)),
#endif
    // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                          const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    pre(new McSimplePreLAG()),
    start(clock::now()),
    mirroring_sessions(new MirroringSessions()) {
  add_component<McSimplePreLAG>(pre);

  add_required_field("tuna_ingress_parser_input_metadata", "packet_path");

  add_required_field("tuna_ingress_input_metadata", "packet_path");
  add_required_field("tuna_ingress_input_metadata", "recircle_timestamp");

  add_required_field("tuna_ingress_output_metadata", "drop");
  add_required_field("tuna_ingress_output_metadata", "len");
  add_required_field("tuna_ingress_output_metadata", "multicast_group");
  add_required_field("tuna_ingress_output_metadata", "clone_session_id");
  add_required_field("tuna_ingress_output_metadata", "clone");
  add_required_field("tuna_ingress_output_metadata", "resubmit");
  add_required_field("tuna_ingress_output_metadata", "class_of_service");
  add_required_field("tuna_ingress_output_metadata", "port");
  add_required_field("tuna_ingress_output_metadata", "ecn");

  add_required_field("tuna_egress_parser_input_metadata", "packet_path");

  add_required_field("tuna_egress_input_metadata", "instance");
  add_required_field("tuna_egress_input_metadata", "packet_path");
  add_required_field("tuna_egress_input_metadata", "recircle_timestamp");

  add_required_field("tuna_egress_output_metadata", "drop");
  add_required_field("tuna_egress_output_metadata", "len");
  add_required_field("tuna_egress_output_metadata", "multicast_group");
  add_required_field("tuna_egress_output_metadata", "clone_session_id");
  add_required_field("tuna_egress_output_metadata", "clone");
  add_required_field("tuna_egress_output_metadata", "resubmit");
  add_required_field("tuna_egress_output_metadata", "class_of_service");
  add_required_field("tuna_egress_output_metadata", "port");

  // 强制算术头处理
  force_arith_header("tuna_ingress_parser_input_metadata");
  force_arith_header("tuna_ingress_input_metadata");
  force_arith_header("tuna_ingress_output_metadata");
  force_arith_header("tuna_egress_parser_input_metadata");
  force_arith_header("tuna_egress_input_metadata");
  force_arith_header("tuna_egress_output_metadata");

  import_primitives();
  import_counters();
  import_meters();
  import_random();
  import_internet_checksum();
  import_hash();
}


int
TunaNic::receive_(port_t port_num, const char *buffer, int len) {
  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);
  auto *phv = packet->get_phv();

  // many current p4 programs assume this
  // from psa spec - PSA does not mandate initialization of user-defined
  // metadata to known values as given as input to the ingress parser
  phv->reset_metadata();

  if (port_num == TUNA_PORT_RX) {
    // data comes from network -> ingress
    phv->get_field("tuna_ingress_parser_input_metadata.packet_path").set(PACKET_PATH_NET_TO_HOST);
    phv->get_field("tuna_ingress_input_metadata.packet_length").set(len);
    enqueue_ingress(std::move(packet));
  } else if (port_num == TUNA_PORT_TX) {
  // each add_header / remove_header primitive call
    phv->get_field("tuna_egress_parser_input_metadata.packet_path").set(PACKET_PATH_HOST_TO_NET);
    phv->get_field("tuna_egress_input_metadata.packet_length").set(len);
    enqueue_egress(std::move(packet));
  } else {
    phv->get_field("tuna_ingress_parser_input_metadata.packet_path").set(PACKET_PATH_NET_TO_HOST);
    phv->get_field("tuna_ingress_input_metadata.packet_length").set(len);
    enqueue_ingress(std::move(packet));
  }
  return 0;
}

void
TunaNic::start_and_return_() {
  for (size_t i = 0; i < nb_ingress_threads; i++) {
    threads_.push_back(std::thread(&TunaNic::ingress_thread, this, i));
  }
  for (size_t i = 0; i < nb_egress_threads; i++) {
    threads_.push_back(std::thread(&TunaNic::egress_thread, this, i));
  }
}

TunaNic::~TunaNic() {
  for (size_t i = 0; i < nb_ingress_threads; i++) {
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    ingress_buffer.push_front(i, 0, nullptr);
#else
    ingress_buffer.push_front(i, nullptr);
#endif
  }
  for (size_t i = 0; i < nb_egress_threads; i++) {
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    egress_buffer.push_front(i, 0, nullptr);
#else
    egress_buffer.push_front(i, nullptr);
#endif
  }

  for (auto& thread_ : threads_) {
    thread_.join();
  }
}

void
TunaNic::reset_target_state_() {
  bm::Logger::get()->debug("Resetting tuna_nic target-specific state");
  get_component<McSimplePreLAG>()->reset_state();
}

bool
TunaNic::mirroring_add_session(mirror_id_t mirror_id,
                                    const MirroringSessionConfig &config) {
  return mirroring_sessions->add_session(mirror_id, config);
}

bool
TunaNic::mirroring_delete_session(mirror_id_t mirror_id) {
  return mirroring_sessions->delete_session(mirror_id);
}

bool
TunaNic::mirroring_get_session(mirror_id_t mirror_id,
                                    MirroringSessionConfig *config) const {
  return mirroring_sessions->get_session(mirror_id, config);
}

int
TunaNic::set_egress_queue_depth(size_t port, const size_t depth_pkts) {
  egress_buffer.set_capacity(port, depth_pkts);
  return 0;
}

int
TunaNic::set_all_egress_queue_depths(const size_t depth_pkts) {
  egress_buffer.set_capacity_for_all(depth_pkts);
  return 0;
}

int
TunaNic::set_egress_queue_rate(size_t port, const uint64_t rate_pps) {
  egress_buffer.set_rate(port, rate_pps);
  return 0;
}

int
TunaNic::set_all_egress_queue_rates(const uint64_t rate_pps) {
  egress_buffer.set_rate_for_all(rate_pps);
  return 0;
}
ts_res
TunaNic::get_ts() const {
  return duration_cast<ts_res>(clock::now() - start);
}
uint64_t
TunaNic::get_time_elapsed_us() const {
  return get_ts().count();
}

uint64_t
TunaNic::get_time_since_epoch_us() const {
  auto tp = clock::now();
  return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void
TunaNic::set_transmit_fn(TransmitFn fn) {
  my_transmit_fn = std::move(fn);
}

void
TunaNic::enqueue_ingress(std::unique_ptr<Packet> &&packet) {
    packet->set_ingress_port(TUNA_PORT_RX);  // 固定为RX端口

#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    auto priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ?
        phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
    if (priority >= SSWITCH_PRIORITY_QUEUEING_NB_QUEUES) {
      bm::Logger::get()->error("Priority out of range, dropping packet");
      return;
    }
    ingress_buffer.push_front(
        TUNA_PORT_RX, SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority,
        std::move(packet));
#else
    ingress_buffer.push_front(TUNA_PORT_RX, std::move(packet));
#endif
}

void
TunaNic::enqueue_egress(std::unique_ptr<Packet> &&packet) {
    packet->set_egress_port(TUNA_PORT_TX);  // 固定为TX端口

#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    auto priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ?
        phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
    if (priority >= SSWITCH_PRIORITY_QUEUEING_NB_QUEUES) {
      bm::Logger::get()->error("Priority out of range, dropping packet");
      return;
    }
    egress_buffer.push_front(
        TUNA_PORT_TX, SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority,
        std::move(packet));
#else
    egress_buffer.push_front(TUNA_PORT_TX, std::move(packet));
#endif
}

void
TunaNic::ingress_thread(size_t worker_id) {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    size_t port;
    ingress_buffer.pop_back(worker_id, &port, &packet);
    if (packet == nullptr) break;

    phv = packet->get_phv();

    /* Ingress cloning and resubmitting work on the packet before parsing.
       `buffer_state` contains the `data_size` field which tracks how many
       bytes are parsed by the parser ("lifted" into p4 headers). Here, we
       track the buffer_state prior to parsing so that we can put it back
       for packets that are cloned or resubmitted, same as in simple_switch.cpp
    */
    // The PSA specification says that for all packets, whether they
    // are new ones from a port, or resubmitted, or recirculated, the
    // ingress_timestamp should be the time near when the packet began
    // ingress processing.  This one place for assigning a value to
    // ingress_timestamp covers all cases.
    // pass relevant values from ingress parser
    // ingress_timestamp is already set above
    Parser *parser = this->get_parser("ingress");
    parser->parse(packet.get());

    phv->get_field("tuna_ingress_input_metadata.packet_path").set(
      phv->get_field("tuna_ingress_parser_input_metadata.packet_path"));
    phv->get_field("tuna_ingress_input_metadata.recircle_timestamp").set(0);

    // set default metadata values according to PSA specification
    phv->get_field("tuna_ingress_output_metadata.drop").set(0);
    phv->get_field("tuna_ingress_output_metadata.len").set(
      phv->get_field("tuna_ingress_input_metadata.packet_length").get_uint());
    phv->get_field("tuna_ingress_output_metadata.multicast_group").set(0);
    phv->get_field("tuna_ingress_output_metadata.clone").set(0);
    phv->get_field("tuna_ingress_output_metadata.clone_session_id").set(0);

    Pipeline *ingress_mau = this->get_pipeline("ingress");
    ingress_mau->apply(packet.get());

    Deparser *deparser = this->get_deparser("ingress");
    deparser->deparse(packet.get());

    auto drop = phv->get_field("tuna_ingress_output_metadata.drop").get_uint();
    if (drop) {
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
      continue;
    }

    auto ecn = phv->get_field("tuna_ingress_output_metadata.ecn").get_uint();
    if (ecn == 1 || ecn == 2) {
      if (ingress_buffer.size(port) > ecn_threshlod) {
        phv->get_field("tuna_ingress_output_metadata.ecn").set(3);
        BMLOG_DEBUG_PKT(*packet, "Congestion experienced, set output_metadata.ecn to 3(CE)");
      }
    }

    auto mgid = phv->get_field("tuna_ingress_output_metadata.multicast_group").get_uint();
    if (mgid != 0) {
      BMLOG_DEBUG_PKT(*packet, "Multicast requested for packet with multicast group {}", mgid);
      multicast(packet.get(), mgid);
      continue;
    }

    // ingress cloning - each cloned packet is a copy of the packet as it entered the ingress parser
    //                 - dropped packets should still be cloned - do not move below drop
    auto clone = phv->get_field("tuna_ingress_output_metadata.clone").get_uint();
    if (clone) {
      MirroringSessionConfig config;
      auto clone_session_id = phv->get_field("tuna_ingress_output_metadata.clone_session_id").get<mirror_id_t>();
      auto is_session_configured = mirroring_get_session(clone_session_id, &config);

      if (is_session_configured) {
        BMLOG_DEBUG_PKT(*packet, "Cloning packet at ingress to session id {}", clone_session_id);
        std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();

        if (config.mgid_valid) {
          BMLOG_DEBUG_PKT(*packet_copy, "Cloning packet to multicast group {}", config.mgid);
          // TODO 0 as the last arg (for class_of_service) is currently a placeholder
          // implement cos into cloning session configs
          multicast(packet_copy.get(), config.mgid);
        }

        if (config.egress_port_valid) {
          BMLOG_DEBUG_PKT(*packet_copy, "Cloning packet to egress port {}", config.egress_port);
          enqueue_egress(std::move(packet_copy)); // fix me, where is the value of egress port comes from?
        }
      }
    }

    // drop - packets marked via the ingress_drop action
    auto packet_path = phv->get_field("tuna_ingress_parser_input_metadata.packet_path").get_uint();
    if (packet_path == PACKET_PATH_NET_TO_HOST) {
      // deparsing, do not move below multicast or deparse
      my_transmit_fn(TUNA_PORT_TX, packet->get_packet_id(),
                     packet->data(), packet->get_data_size());
      BMELOG(packet_out, *packet);
      BMLOG_DEBUG_PKT(*packet, "Ingress thread {} transmitting packet to host", worker_id);
    } else if (packet_path == PACKET_PATH_R2T) {
      phv->get_field("tuna_egress_parser_input_metadata.packet_path").set(PACKET_PATH_R2T);
      enqueue_egress(std::move(packet));
      BMELOG(packet_out, *packet);
      BMLOG_DEBUG_PKT(*packet, "Ingress thread {} loopback packet to network", worker_id);
    } else {
      BMELOG(packet_out, *packet);
      my_transmit_fn(TUNA_PORT_TX, packet->get_packet_id(),
                     packet->data(), packet->get_data_size());
      BMELOG(packet_out, *packet);
      BMLOG_DEBUG_PKT(*packet, "Ingress thread {} transmitting packet defaultly to host", worker_id);
    }
  }
}

void
TunaNic::egress_thread(size_t worker_id) {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    size_t port;

    egress_buffer.pop_back(worker_id, &port, &packet);

    if (packet == nullptr) break;
    phv = packet->get_phv();

    // this reset() marks all headers as invalid - this is important since PSA
    // deparses packets after ingress processing - so no guarantees can be made
    // about their existence or validity while entering egress processing
    Parser *parser = this->get_parser("egress");
    parser->parse(packet.get());

    phv->get_field("tuna_egress_input_metadata.packet_path").set(
      phv->get_field("tuna_egress_parser_input_metadata.packet_path"));
    phv->get_field("tuna_egress_input_metadata.recircle_timestamp").set(0);

    // default egress output values according to PSA spec
    // clone_session_id is undefined by default
    phv->get_field("tuna_egress_output_metadata.drop").set(0);

    Pipeline *egress_mau = this->get_pipeline("egress");
    egress_mau->apply(packet.get());

    Deparser *deparser = this->get_deparser("egress");
    deparser->deparse(packet.get());

    // 检查 drop
    // egress cloning - each cloned packet is a copy of the packet as output by the egress deparser
    auto drop = phv->get_field("tuna_egress_output_metadata.drop").get_uint();
    if (drop) {
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
      continue;
          // implement cos into cloning session configs
    }

    auto packet_path = phv->get_field("tuna_egress_parser_input_metadata.packet_path").get_uint();
    if (packet_path == PACKET_PATH_HOST_TO_NET) {
      BMELOG(packet_out, *packet);
      BMLOG_DEBUG_PKT(*packet, "Egress thread {} transmitting packet to network", worker_id);
      my_transmit_fn(TUNA_PORT_RX, packet->get_packet_id(),
                     packet->data(), packet->get_data_size());
    } else if (packet_path == PACKET_PATH_T2R) {
      BMELOG(packet_out, *packet);
      BMLOG_DEBUG_PKT(*packet, "Egress thread {} loopback packet to host", worker_id);
      enqueue_ingress(std::move(packet));
    } else {
      BMELOG(packet_out, *packet);
      BMLOG_DEBUG_PKT(*packet, "Egress thread {} transmitting packet defaultly to network", worker_id);
      my_transmit_fn(TUNA_PORT_RX, packet->get_packet_id(),
                     packet->data(), packet->get_data_size());
    }
  }
}

void
TunaNic::multicast(Packet *packet, unsigned int mgid) {
  auto *phv = packet->get_phv();
  const auto pre_out = pre->replicate({mgid});

  auto packet_size = phv->get_field("tuna_ingress_input_metadata.packet_length").get_uint();
  for (const auto &out : pre_out) {
    auto egress_port = out.egress_port;
    BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
    std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();
    phv->get_field("tuna_egress_input_metadata.packet_length").set(packet_size);
    enqueue_egress(std::move(packet_copy));
  }
}

}  // namespace bm::tuna

}  // namespace bm

