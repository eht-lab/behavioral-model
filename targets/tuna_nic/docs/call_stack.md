# Tuna NIC SW call stack

本文档详细记录了bmv2 tuna_nic target的完整软件调用链, 包括初始化、transimt和receive两个核心流程。

- 类继承关系
```
TunaNic → Switch → SwitchWContexts
```
**关键点**:
- TunaNic 虽然是网卡, 但是也继承了bmv2 里的switch类
- `TunaNic`重写了`SwitchWContexts`的虚函数`receive_`, 所以当调用`this->receive_()`时, 会自动调用`TunaNic::receive_`。


1. 初始化过程
```
main()
  → TunaNic::init_from_command_line_options()
    → parser.parse
      → OptionsParser::parse
        → ifaces.add
    → SwitchWContexts::init_from_options_parser()  // 打开veth获取fd, run_select 里监控所有的网口
      → DevMgr::port_add
        → bmi_port_interface_add
           → _bmi_port_interface_add
              → bmi_interface_create
              → fd = bmi_interface_get_fd(port->bmi)
      → set_packet_handler(packet_handler, this) // 设置handler, 形成对receive_ 的回调
        → bmi_set_packet_handler()
```

2. 启动过程
```
main()
  → TunaNic::start_and_return()
    → SwitchWContexts::start_and_return()
      → DevMgr::start()
        → BmiDevMgrImp::start_()
          → bmi_start_mgr()
            → run_select线程启动
```

3. 调用过程
```
veth接口收到数据包
  → run_select线程检测到
    → bmi_interface_recv()
    → port_mgr->packet_handler()
      → packet_handler()
        → SwitchWContexts::receive()
          → TunaNic::receive_()
```

**关键点总结**
1. `this`指针传递: 在第4步中, `this`实际上是`TunaNic*`指针, 通过继承关系传递给`packet_handler`
2. 虚函数机制: `TunaNic::receive_`是通过C++虚函数机制自动传递的, 而不是通过函数参数
3. 线程模型: `receive_()`不是独立线程, 而是由`run_select`线程同步调用的回调函数
4. 参数传递: `argc, argv, tuna_nic_parser`只是用于解析命令行参数, 真正的`TunaNic::receive_`是通过`this`指针和虚函数表传递的
5. 数据包流转: 当veth接口收到数据包时, 会触发完整的调用链, 最终调用到`TunaNic::receive_`方法

下面展开各个过程的详细过程。
<br>


## 初始化过程

### 主线流程
从main函数开始, 按照实际调用顺序展开:

1. main函数创建TunaNic对象
文件: `behavioral-model/targets/tuna_nic/main.cpp`: 第40行
    ```cpp
    tuna_nic = new TunaNic();
    ```

2. 调用init_from_command_line_options
文件: `behavioral-model/targets/tuna_nic/main.cpp`: 第44-46行
    ```cpp
    int status = tuna_nic->init_from_command_line_options(
        argc, argv, tuna_nic_parser);
    ```

3. SwitchWContexts::init_from_command_line_options
文件: `behavioral-model/src/bm_sim/switch.cpp`: 第210-218行
    ```cpp
    int SwitchWContexts::init_from_command_line_options(
        int argc, char *argv[], TargetParserIface *tp,
        std::shared_ptr<TransportIface> my_transport,
        std::unique_ptr<DevMgrIface> my_dev_mgr) {
      OptionsParser parser;
      parser.parse(argc, argv, tp);  // 调用OptionsParser::parse解析命令行, 在第4点展开描述
      return init_from_options_parser(parser, my_transport, std::move(my_dev_mgr)); // 在第7点展开描述
    }
    ```

4. OptionsParser::parse解析命令行参数
从第3点展开而来
文件: `behavioral-model/src/bm_sim/options_parse.cpp`: 第87-120行
    ```cpp
    void OptionsParser::parse(int argc, char *argv[], TargetParserIface *tp,
                             std::ostream &outstream) {
      namespace po = boost::program_options;

      po::options_description description("Options");
      description.add_options()
          ("interface,i", po::value<std::vector<interface> >()->composing(),
           "<port-num>@<interface-name>: "
           "Attach network interface <interface-name> as port <port-num> at "
           "startup. Can appear multiple times");
      // ... 其他选项定义

      po::variables_map vm;
      auto parser = po::command_line_parser(argc, argv);
      parser.options(options).positional(positional);
      po::parsed_options parsed = parser.run();
      po::store(parsed, vm);  // 这里会调用validate函数解析interface参数
      po::notify(vm);
    }
    ```

5. boost::program_options::store调用validate函数解析interface参数
文件: `behavioral-model/src/bm_sim/options_parse.cpp`: 第51-85行
    ```cpp
    void validate(boost::any& v, const std::vector<std::string> &values,
                  interface* /* target_type */, int) {
      // 解析 <port-num>@<interface-name> 格式
      const std::string &s = po::validators::get_single_string(values);
      std::istringstream stream(s);
      std::string tok;
      std::getline(stream, tok, '@');
      uint32_t port = std::stoi(tok, nullptr);
      std::getline(stream, tok);
      v = boost::any(interface(tok, port));
    }
    ```

6. OptionsParser::parse处理解析后的接口列表
文件: `behavioral-model/src/bm_sim/options_parse.cpp`: 第342-346行
    ```cpp
    if (vm.count("interface")) {
      for (const auto &iface : vm["interface"].as<std::vector<interface> >()) {
        ifaces.add(iface.port, iface.name);  // 添加到ifaces容器
      }
    }
    ```

7. SwitchWContexts::init_from_options_parser处理接口添加
从第3点展开而来
文件: `behavioral-model/src/bm_sim/switch.cpp`: 第280-310行
    ```cpp
    for (const auto &iface : parser.ifaces) {
      std::cout << "Adding interface " << iface.second
                << " as port " << iface.first << std::endl;

      PortExtras port_extras;
      if (!inFile.empty())
        port_extras.emplace(DevMgrIface::kPortExtraInPcap, inFile);
      if (!outFile.empty())
        port_extras.emplace(DevMgrIface::kPortExtraOutPcap, outFile);
      port_add(iface.second, iface.first, port_extras);  // 调用DevMgr::port_add
    }
    ```

8. DevMgr::port_add调用pimp->port_add
文件: `behavioral-model/src/bm_sim/dev_mgr.cpp`: 第214-220行
    ```cpp
    PacketDispatcherIface::ReturnCode
    DevMgr::port_add(const std::string &iface_name, port_t port_num,
                     const PortExtras &port_extras) {
      assert(pimp);
      ReturnCode rc = pimp->port_add(iface_name, port_num, port_extras);  // 调用BmiDevMgrImp::port_add_
      return rc;
    }
    ```

9. BmiDevMgrImp::port_add_调用bmi_port_interface_add
文件: `behavioral-model/src/bm_sim/dev_mgr_bmi.cpp`: 第62-75行
    ```cpp
    ReturnCode port_add_(const std::string &iface_name, port_t port_num,
                         const PortExtras &port_extras) override {
      if (bmi_port_interface_add(port_mgr, iface_name.c_str(), port_num, in_pcap,
                                 out_pcap))  // 调用bmi_port_interface_add
        return ReturnCode::ERROR;
      // ...
    }
    ```

10.  bmi_port_interface_add调用_bmi_port_interface_add
文件: `behavioral-model/src/BMI/bmi_port.c`: 第295-305行
    ```c
    int bmi_port_interface_add(bmi_port_mgr_t *port_mgr,
                               const char *ifname, int port_num,
                               const char *pcap_input_dump,
                               const char* pcap_output_dump) {
      int exitCode;
      pthread_rwlock_wrlock(&port_mgr->lock);
      exitCode = _bmi_port_interface_add(port_mgr, ifname, port_num,
                                         pcap_input_dump, pcap_output_dump);  // 调用_bmi_port_interface_add
      pthread_rwlock_unlock(&port_mgr->lock);
      return exitCode;
    }
    ```

11.  _bmi_port_interface_add调用bmi_interface_create
文件: `behavioral-model/src/BMI/bmi_port.c`: 第260-295行
    ```c
    static int _bmi_port_interface_add(bmi_port_mgr_t *port_mgr,
                                       const char *ifname, int port_num,
                                       const char *pcap_input_dump,
                                       const char* pcap_output_dump) {
      bmi_port_t *port = get_port(port_mgr, port_num);
      if (port) return -1;  // port already in use

      bmi_interface_t *bmi;
      if (bmi_interface_create(&bmi, ifname) != 0) return -1;  // 调用bmi_interface_create

      port = insert_port(port_mgr, port_num);
      port->port_num = port_num;
      port->ifname = strdup(ifname);
      port->bmi = bmi;

      int fd = bmi_interface_get_fd(port->bmi);  // 调用bmi_interface_get_fd
      port->fd = fd;
      if (fd > port_mgr->max_fd) port_mgr->max_fd = fd;
      FD_SET(fd, &port_mgr->fds);
      port_mgr->port_count++;
      return 0;
    }
    ```

12.  bmi_interface_create 创建PCAP接口并获取FD
文件: `behavioral-model/src/BMI/bmi_interface.c`: 第40-85行
    ```c
    int bmi_interface_create(bmi_interface_t **bmi, const char *device) {
      bmi_->pcap = pcap_create(device, errbuf);  // 调用libpcap创建接口
      pcap_set_promisc(bmi_->pcap, 1);  // 设置混杂模式
      pcap_activate(bmi_->pcap);  // 激活接口
      bmi_->fd = pcap_get_selectable_fd(bmi_->pcap);  // 获取可选择的fd
      // ...
    }
    ```

13.  SwitchWContexts::init_from_options_parser设置packet_handler
继续第7点对init_from_options_parser的展开, 内容设计tuna的receive_ 函数被调用的原理, 即packet_handler的初始化过程
文件: `behavioral-model/src/bm_sim/switch.cpp`: 第324行
    ```cpp
    set_packet_handler(packet_handler, static_cast<void *>(this));
    ```

**关键说明**: 这里的`this`是`SwitchWContexts*`类型, 但由于`TunaNic`继承自`Switch`, 而`Switch`继承自`SwitchWContexts`, 所以实际上`this`指向的是`TunaNic`对象。通过`static_cast<void *>(this)`将`TunaNic*`转换为`void*`传递给`packet_handler`。

14. 全局packet_handler函数
文件: `behavioral-model/src/bm_sim/switch.cpp`: 第48-52行
    ```cpp
    static void
    packet_handler(int port_num, const char *buffer, int len, void *cookie) {
      // static_cast<SwitchWContexts *> if okay here because cookie was obtained by
      // casting a SwitchWContexts * to void *
      static_cast<SwitchWContexts *>(cookie)->receive(port_num, buffer, len);
    }
    ```

15. DevMgr::set_packet_handler
文件: `behavioral-model/src/bm_sim/dev_mgr.cpp`: 第250-253行
    ```cpp
    PacketDispatcherIface::ReturnCode
    DevMgr::set_packet_handler(const PacketHandler &handler, void *cookie) {
      assert(pimp);
      return pimp->set_packet_handler(handler, cookie);
    }
    ```

16. BmiDevMgrImp::set_packet_handler_
文件: `behavioral-model/src/bm_sim/dev_mgr_bmi.cpp`: 第95-105行
    ```cpp
    ReturnCode set_packet_handler_(const PacketHandler &handler, void *cookie)
        override {
      using function_t = void(int, const char *, int, void *);
      function_t * const*ptr_fun = handler.target<function_t *>();
      assert(ptr_fun);
      assert(*ptr_fun);
      if (bmi_set_packet_handler(port_mgr, *ptr_fun, cookie)) {
        Logger::get()->critical("Could not set BMI packet handler");
        return ReturnCode::ERROR;
      }
      return ReturnCode::SUCCESS;
    }
    ```

17. bmi_set_packet_handler
文件: `behavioral-model/src/BMI/bmi_port.c`: 第227-233行
    ```c
    int bmi_set_packet_handler(bmi_port_mgr_t *port_mgr,
                               bmi_packet_handler_t packet_handler,
                               void *cookie) {
      pthread_rwlock_wrlock(&port_mgr->lock);
      port_mgr->packet_handler = packet_handler;
      port_mgr->cookie = cookie;
      pthread_rwlock_unlock(&port_mgr->lock);
      return 0;
    }
    ```

### Veth接口fd初始化

FD赋值机制总结:
- 命令行解析: 通过`--interface <port-num>@<interface-name>`参数指定端口号和接口名
- PCAP接口创建: 每个veth接口调用`bmi_interface_create`创建独立的pcap接口
- FD获取: 通过`pcap_get_selectable_fd()`从pcap接口获取可选择的文件描述符
- FD存储: 将fd存储在`bmi_port_t`结构中, 并添加到`port_mgr->fds`集合中供select监听

**多网卡示例**:
```bash
# 启动tuna_nic, 绑定两个veth接口
./tuna_nic --interface 0@veth0 --interface 1@veth1 config.json
```
- veth0映射到端口0, veth1映射到端口1
- 每个接口有独立的fd和pcap接口
- 数据包通过端口号区分来源和目标

## 启动过程

1. main函数调用start_and_return
文件: `behavioral-model/targets/tuna_nic/main.cpp`: 第48行
    ```cpp
    tuna_nic->start_and_return();
    ```

2. SwitchWContexts::start_and_return
文件: `behavioral-model/src/bm_sim/switch.cpp`: 第78-90行
    ```cpp
    void SwitchWContexts::start_and_return() {
      std::unique_lock<std::mutex> config_lock(config_mutex);
      if (!config_loaded && !enable_swap) {
        Logger::get()->error(
            "The switch was started with no P4 and config swap is disabled");
      }
      config_loaded_cv.wait(config_lock, [this]() { return config_loaded; });
      start();  // DevMgr::start
      start_and_return_();
      PeriodicTaskList::get_instance().start();
    }
    ```

3. DevMgr::start
文件: `behavioral-model/src/bm_sim/dev_mgr.cpp`: 第140-143行
    ```cpp
    void DevMgr::start() {
      assert(pimp);
      pimp->start();
    }
    ```

4. BmiDevMgrImp::start_
文件: `behavioral-model/src/bm_sim/dev_mgr_bmi.cpp`: 第85-89行
    ```cpp
    void start_() override {
      assert(port_mgr);
      if (bmi_start_mgr(port_mgr))
        Logger::get()->critical("Could not start BMI port manager");
    }
    ```

5. bmi_start_mgr启动select线程
文件: `behavioral-model/src/BMI/bmi_port.c`: 第184-186行
    ```c
    int bmi_start_mgr(bmi_port_mgr_t* port_mgr) {
      return pthread_create(&port_mgr->select_thread, NULL, run_select, port_mgr);
    }
    ```

## Receive

### 主线流程
当veth接口收到数据包时:

1. run_select线程监听veth接口
文件: `behavioral-model/src/BMI/bmi_port.c`: 第117-183行
    ```c
    static void *run_select(void *data) {
      bmi_port_mgr_t *port_mgr = (bmi_port_mgr_t *) data;
      // ... 监听所有veth接口的fd
      while(1) {
        n = select(max_fd + 1, &fds, NULL, NULL, &timeout);
        // ... 检查哪个接口有数据
        if (FD_ISSET(port->fd, &fds)) {
          pkt_len = bmi_interface_recv(port->bmi, &pkt_data);
          if (pkt_len >= 0) {
            assert(port_mgr->packet_handler);
            port_mgr->packet_handler(
                port->port_num, pkt_data, pkt_len, port_mgr->cookie);
          }
        }
      }
    }
    ```

2. packet_handler被调用
文件: `behavioral-model/src/bm_sim/switch.cpp`: 第48-52行
    ```cpp
    static void
    packet_handler(int port_num, const char *buffer, int len, void *cookie) {
      static_cast<SwitchWContexts *>(cookie)->receive(port_num, buffer, len);
    }
    ```

3. SwitchWContexts::receive被调用
文件: `behavioral-model/src/bm_sim/switch.cpp`: 第68-76行
    ```cpp
    int SwitchWContexts::receive(port_t port_num, const char *buffer, int len) {
      if (dump_packet_data > 0) {
        Logger::get()->info("Received packet of length {} on port {}: {}",
                            len, port_num, sample_packet_data(buffer, len));
      }
      return receive_(port_num, buffer, len);  // 调用虚函数
    }
    ```

4. TunaNic::receive_被调用
文件: `behavioral-model/targets/tuna_nic/tuna_nic.cpp`: 第190行开始
    ```cpp
    int TunaNic::receive_(port_t port_num, const char *buffer, int len) {
      // TunaNic的具体实现
    }
    ```

### 多网卡处理机制

**关键点总结**:
- 端口号映射: 每个veth接口通过命令行参数映射到唯一的端口号
- 独立结构: 每个端口有独立的`bmi_port_t`结构和`bmi_interface_t`
- 统一监听: `run_select`线程通过select监听所有端口的fd
- 端口标识: 接收时通过`port->port_num`标识数据包来源
- 线程安全: 使用读写锁保护端口管理器的并发访问

**多网卡监听机制**:
1. bmi_start_mgr启动统一的监听线程
文件: `behavioral-model/src/BMI/bmi_port.c`: 第184-186行
    ```c
    int bmi_start_mgr(bmi_port_mgr_t* port_mgr) {
      return pthread_create(&port_mgr->select_thread, NULL, run_select, port_mgr);  // 创建run_select线程
    }
    ```

2. run_select线程监听所有接口的FD
文件: `behavioral-model/src/BMI/bmi_port.c`: 第117-183行
    ```c
    static void *run_select(void *data) {
      bmi_port_mgr_t *port_mgr = (bmi_port_mgr_t *) data;
      while(1) {
        n = select(max_fd + 1, &fds, NULL, NULL, &timeout);  // 调用select系统调用
        int idx = 0;
        while (n && idx < port_mgr->port_count) {
          port = &port_mgr->ports[idx];
          if (FD_ISSET(port->fd, &fds)) {
            pkt_len = bmi_interface_recv(port->bmi, &pkt_data);  // 调用bmi_interface_recv
            if (pkt_len >= 0) {
              port_mgr->packet_handler(
                  port->port_num, pkt_data, pkt_len, port_mgr->cookie);  // 调用packet_handler
            }
          }
          ++idx;
        }
      }
    }
    ```

## Transmit

### 主线流程
```
TunaNic::transmit_thread()
  → my_transmit_fn(...)
  → TunaNic::transmit_fn(...)
  → DevMgr::transmit_fn(...)
  → BmiDevMgrImp::transmit_fn_(...)
  → bmi_port_send(...)
  → bmi_interface_send(...)
  → write/sendto系统调用写入veth
```

### 关键点总结

1. my_transmit_fn: TunaNic 构造时设置, 最终调用 TunaNic::transmit_fn
2. transmit_fn: 通过 DevMgr 层层转发, 最终调用 BMI 层的 bmi_port_send
3. bmi_port_send: 调用底层 bmi_interface_send, 真正写入 veth 设备
4. bmi_interface_send: 底层通过 write/sendto 系统调用将数据写入 veth 设备的 fd
5. 线程模型: transmit_thread 是 TunaNic 的独立线程, 循环从 output_buffer 取包并发送
6. 数据流转: output_buffer → transmit_thread → veth

### 详细过程展开

1. TunaNic::transmit_thread 线程循环取包
文件: `behavioral-model/targets/tuna_nic/tuna_nic.cpp`: 第500行起
    ```cpp
    void TunaNic::transmit_thread() {
      while (1) {
        std::unique_ptr<Packet> packet;
        output_buffer.pop_back(&packet);
        if (packet == nullptr) break;
        my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                       packet->data(), packet->get_data_size());
      }
    }
    ```

2. my_transmit_fn 实际调用 TunaNic::transmit_fn
文件: `behavioral-model/targets/tuna_nic/tuna_nic.cpp`: TunaNic 构造函数
    ```cpp
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                          const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    ```

3. TunaNic::transmit_fn 调用 DevMgr::transmit_fn
文件: `behavioral-model/src/bm_sim/switch.cpp`
    ```cpp
    void Switch::transmit_fn(port_t port_num, const char *buffer, int len) {
      dev_mgr->transmit_fn(port_num, buffer, len);
    }
    ```

4. DevMgr::transmit_fn 调用 pimp->transmit_fn
文件: `behavioral-model/src/bm_sim/dev_mgr.cpp`: 第230-238行
    ```cpp
    void DevMgr::transmit_fn(port_t port_num, const char *buffer, int len) {
      assert(pimp);
      pimp->transmit_fn(port_num, buffer, len);
    }
    ```

5. BmiDevMgrImp::transmit_fn_ 调用 bmi_port_send
文件: `behavioral-model/src/bm_sim/dev_mgr_bmi.cpp`: 第75-77行
    ```cpp
    void transmit_fn_(port_t port_num, const char *buffer, int len) override {
      bmi_port_send(port_mgr, port_num, buffer, len);
    }
    ```

6. bmi_port_send 调用 bmi_interface_send
文件: `behavioral-model/src/BMI/bmi_port.c`: 第240-250行
    ```c
    int bmi_port_send(bmi_port_mgr_t *port_mgr,
                      int port_num, const char *buffer, int len) {
      bmi_port_t *port = get_port(port_mgr, port_num);
      int exitCode = bmi_interface_send(port->bmi, buffer, len);
      // ...
    }
    ```

7. bmi_interface_send 通过 write/sendto 写入 veth
文件: `behavioral-model/src/BMI/bmi_interface.c`
核心代码（以 write 为例, 实际可能有 sendto 分支）:
    ```c
    int bmi_interface_send(bmi_interface_t *bmi, const char *buffer, int len) {
      // ...
      int n = write(bmi->fd, buffer, len);
      // 或
      // int n = sendto(bmi->fd, buffer, len, 0, ...);
      // ...
      return n;
    }
    ```
- 其中 `bmi->fd` 就是 veth 设备的文件描述符, 数据最终通过内核写入 veth 设备, 主机或对端容器即可收到数据包。

### 多网卡发送机制

**关键点总结**:
- 端口号映射: 发送时通过`port_num`参数确定目标端口
- 端口查找: 通过`get_port(port_mgr, port_num)`根据端口号查找对应的端口结构
- 独立fd: 每个端口有独立的`bmi_interface_t`和对应的fd
- 线程安全: 使用读写锁保护端口管理器的并发访问

**多网卡发送机制**:
1. 发送时通过端口号区分目标接口
文件: `behavioral-model/src/BMI/bmi_port.c`: 第237-250行
    ```c
    int bmi_port_send(bmi_port_mgr_t *port_mgr,
                      int port_num, const char *buffer, int len) {
      bmi_port_t *port = get_port(port_mgr, port_num);  // 根据端口号查找端口
      if (!port) return -1;
      int exitCode = bmi_interface_send(port->bmi, buffer, len);  // 调用bmi_interface_send
      return exitCode;
    }
    ```

<br>
<br>

## 多线程队列机制

tuna_nic target采用了PSA规范的多线程队列机制, 通过`ingress/egress_buffer`实现高并发的数据包处理。这套机制包含逻辑队列、物理队列、worker线程等核心概念。

- 机制优势
  - **高并发处理**:多个(4) worker线程并行处理ingress/egress pipeline
  - **负载均衡**: 端口通过取模算法均匀分布到worker
  - **减少锁竞争**: 不同worker处理不同端口

- 灵活的队列管理
   - **速率控制**: 每个逻辑队列可以独立设置PPS限制
   - **容量控制**: 每个逻辑队列有独立的容量限制
   - **优先级支持**: 支持多优先级队列（如果启用）

- 非阻塞设计
   - **队列满时丢弃**: 避免阻塞整个系统
   - **条件变量通知**: 高效的线程同步机制
   - **优先级队列**: 基于时间戳的精确调度


### 核心组件
1. 线程初始化
位置: `behavioral-model/targets/tuna_nic/tuna_nic.cpp:227-229`
    ```cpp
    void TunaNic::start_and_return_() {
      for (size_t i = 0; i < nb_ingress_threads; i++) {  // 创建4个worker线程
        threads_.push_back(std::thread(&TunaNic::ingress_thread, this, i));
      }
      for (size_t i = 0; i < nb_egress_threads; i++) {  // 创建4个worker线程
        threads_.push_back(std::thread(&TunaNic::egress_thread, this, i));
      }
    }
    ```

- 关键点:
   - 在初始化时启动nb_ingress/egress_threads（4/4）个ingress/egress_thread
   - 每个线程的worker_id不同: 0, 1, 2, 3
   - 总共8个线程: 4个ingress + 4个egress

1. 队列映射机制
位置: `behavioral-model/targets/tuna_nic/tuna_nic.h:240-250`
   ```cpp
   struct EgressThreadMapper {
     explicit EgressThreadMapper(size_t nb_threads)
         : nb_threads(nb_threads) { }

     size_t operator()(size_t egress_port) const {
       return egress_port % nb_threads;  // 简单的取模映射算法
     }

     size_t nb_threads;
   };
   ```

**映射关系**:
- 端口0/4 ... → worker 0
- 端口1/5 ... → worker 1
- 端口2/6 ... → worker 2
- 端口3/7 ... → worker 3
-
3. 队列结构设计
逻辑队列（按端口） 物理队列（按线程）
┌─────────────┐ ┌─────────────┐
│ 端口0队列 │ ──映射──→│ Worker0队列 │
└─────────────┘ └─────────────┘
┌─────────────┐ ┌─────────────┐
│ 端口1队列 │ ──映射──→│ Worker1队列 │
└─────────────┘ └─────────────┘
┌─────────────┐ ┌─────────────┐
│ 端口2队列 │ ──映射──→│ Worker2队列 │
└─────────────┘ └─────────────┘
┌─────────────┐ ┌─────────────┐
│ 端口3队列 │ ──映射──→│ Worker3队列 │
└─────────────┘ └─────────────┘

**关键概念**:
- 逻辑队列: 从端口角度看的虚拟队列, 有独立的容量和速率限制
- 物理队列: 从线程角度看的实际存储结构（`std::priority_queue`）
- 映射关系: 通过`EgressThreadMapper`建立端口到worker的映射

### 数据包流转算法

1. Push算法（数据包入队）
位置: `behavioral-model/include/bm/bm_sim/queueing.h:270-285`

```cpp
int push_front(size_t queue_id, T &&item) {
  size_t worker_id = map_to_worker(queue_id);  // 1. 端口映射到worker
  LockType lock(mutex);
  auto &q_info = get_queue(queue_id);          // 2. 获取逻辑队列信息
  auto &w_info = workers_info.at(worker_id);   // 3. 获取物理队列信息

  if (q_info.size >= q_info.capacity) return 0; // 4. 队列满则丢弃

  q_info.last_sent = get_next_tp(q_info);      // 5. 计算下次发送时间（速率控制）
  w_info.queue.emplace(                        // 6. 放入物理队列
      std::move(item), queue_id, q_info.last_sent, w_info.wrapping_counter++);
  q_info.size++;                               // 7. 更新逻辑队列大小
  w_info.q_not_empty.notify_one();             // 8. 通知worker线程
  return 1;
}
```

算法步骤:
 - 端口映射: 通过`EgressThreadMapper`将端口映射到worker
 - 容量检查: 检查逻辑队列是否已满
 - 速率控制: 计算下次发送时间（支持PPS限制）
 - 入队操作: 将数据包放入对应的物理队列
 - 状态更新: 更新逻辑队列大小和通知机制

2. Pop算法（数据包出队）
位置: `behavioral-model/include/bm/bm_sim/queueing.h:287-305`
   ```cpp
   void pop_back(size_t worker_id, size_t *queue_id, T *pItem) {
     LockType lock(mutex);
     auto &w_info = workers_info.at(worker_id);
     auto &queue = w_info.queue;

     while (true) {
       if (queue.size() == 0) {
         w_info.q_not_empty.wait(lock);           // 1. 队列空则等待
       } else {
         if (queue.top().send <= clock::now()) break; // 2. 检查速率限制
         w_info.q_not_empty.wait_until(lock, queue.top().send);
       }
     }

     *queue_id = queue.top().queue_id;            // 3. 获取逻辑队列ID
     *pItem = std::move(const_cast<QE &>(queue.top()).e); // 4. 取出数据包
     queue.pop();                                 // 5. 从物理队列移除
     auto &q_info = get_queue_or_throw(*queue_id);
     q_info.size--;                               // 6. 更新逻辑队列大小
   }
   ```

算法步骤:
- 等待机制: 如果队列为空, 线程阻塞等待
- 速率控制: 检查数据包是否到了发送时间
- 出队操作: 从优先级队列顶部取出数据包
- 状态更新: 更新逻辑队列大小

3. enqueue函数原理
位置: `behavioral-model/targets/tuna_nic/tuna_nic.cpp:330-345`
   ```cpp
   void TunaNic::enqueue(port_t egress_port, std::unique_ptr<Packet> &&packet) {
       packet->set_egress_port(egress_port);  // 设置出端口

   #ifdef SSWITCH_PRIORITY_QUEUEING_ON
       // 优先级队列模式
       auto priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ?
           phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
       egress_buffers.push_front(egress_port, priority, std::move(packet));
   #else
       // 普通队列模式
       egress_buffers.push_front(egress_port, std::move(packet));
   #endif
   }
   ```

调用时机:
- ingress处理完成: 在ingress_thread中处理完数据包后调用
- 多播复制: 在multicast函数中复制数据包时调用
- 镜像处理: 在镜像处理中调用

### Worker线程处理流程

1. egress_thread函数
位置: `behavioral-model/targets/tuna_nic/tuna_nic.cpp:435-486`
   ```cpp
   void TunaNic::egress_thread(size_t worker_id) {
     PHV *phv;

     while (1) {
       std::unique_ptr<Packet> packet;
       size_t port;
       egress_buffers.pop_back(worker_id, &port, &packet); // 从对应worker队列取包

       if (packet == nullptr) break;
       phv = packet->get_phv();

       // 设置egress输入metadata
       phv->get_field("tuna_egress_input_metadata.packet_path").set(
           phv->get_field("tuna_egress_parser_input_metadata.packet_path"));

       // 执行egress pipeline
       Pipeline *egress_mau = this->get_pipeline("egress");
       egress_mau->apply(packet.get());

       // 根据数据包路径决定处理方式
       auto packet_path = phv->get_field("tuna_egress_parser_input_metadata.packet_path").get_uint();

       if (packet_path == FROM_HOST) {
         output_buffer.push_front(std::move(packet));  // 正常发送
       } else if (packet_path == FROM_HOST_LOOPEDBACK) {
         input_buffer.push_front(std::move(packet));   // 重新进入ingress
       } else {
         output_buffer.push_front(std::move(packet));  // 默认处理
       }
     }
   }
   ```


## buffer

tuna的数据链路设计:
1. Normal RX (FROM_NET_PORT): 网络 → 主机
receive_() → ingress_buffer → host

2. Normal TX (FROM_HOST): 主机 → 网络
receive_() → egress_buffer → net

3. R2T (FROM_NET_LOOPEDBACK): 网络 → 网络（回环）
receive_() → ingress_buffer → egress_buffer → net

4. T2R (FROM_HOST_LOOPEDBACK): 主机 → 主机（回环）
receive_() → egress_buffer → ingress_buffer → host

## Tuna数据链路设计

tuna网卡的数据链路设计包含4条路径:
1. **Normal RX (FROM_NET_PORT)**: 网络 → 主机
   ```
   receive_() → ingress_buffer → host
   ```
2. **Normal TX (FROM_HOST)**: 主机 → 网络
   ```
   receive_() → egress_buffer → net
   ```
3. **R2T (FROM_NET_LOOPEDBACK)**: 网络 → 网络（回环）
   ```
   receive_() → ingress_buffer → egress_buffer → net
   ```
4. **T2R (FROM_HOST_LOOPEDBACK)**: 主机 → 主机（回环）
   ```
   receive_() → egress_buffer → ingress_buffer → host
   ```

**具体说明**:
- p4c-apollo-tuna 通过三个"-i ${port_id}@veth${port_id} 来传入三组port
  - port0 表示host ↔ bmv2
  - port1 表示transmit时的port
  - 对比PNA target, Transmit 是由用户在p4 程序里通过send_to_port() 显示的设置port来决定往哪个网卡发
- 两个tuna nic 使用3组veth 来实现互联:
   ```bash
   h1_eth0 ↔ tuna1_eth1 ↔ tuna1_eth0
                              ↓ pair
   h2_eth0 ↔ tuna2_eth1 ↔ tuna2_eth0
   ```
- 设置2个buffer
  - ingress_buffer: 保存ingress方向的数据包
  - egress_buffer: 保存egress方向的数据包
  - 没有input_buffer和output_buffer
- 2种thread
  - 多个ingress_thread和egress_thread, 具体个数有定义的nb_xgress_threads定义
    - receive_()根据port_id直接判断进入ingress_buffer还是egress_buffer
  - 没有my_transmit_fn
    - ingress_thread和egress_thread 执行完规定的各种操作直接执行my_transmit_fn
  - 因为没有input_buffer和output_buffer, 也没有一个专用的transmit_thread负责将数据包从bmv2 发送出去，因此增加ingress_thread和egress_thread 个数，试图弥补由此带来的并发效率问题

- 以h1 ping h2 为例，数据包经过的数据链路如下：
  - ICMP Request
     - h1发送ping → h1-eth0 → tuna1-eth1 → Tuna1进程receive_()
     - Tuna1处理 → FROM_HOST路径 → egress_buffer → egress_thread → my_transmit_fn
     - Tuna1发送 → tuna1-eth0 → Linux内核veth pair → tuna2-eth0
     - Tuna2接收 → receive_() → FROM_NET_PORT路径 → ingress_thread → my_transmit_fn
     - Tuna2发送 → tuna2-eth1 → h2-eth0 → h2收到ping
