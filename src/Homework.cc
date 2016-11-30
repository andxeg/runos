#include "Homework.hh"

#include <ctime>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cstdio>
#include <vector>
#include <utility>
#include <random>
#include <algorithm>

#include "api/Packet.hh"
#include "api/PacketMissHandler.hh"
#include "api/TraceablePacket.hh"
#include "oxm/openflow_basic.hh"
#include "types/ethaddr.hh"

#include "Controller.hh"
#include "HostManager.hh"
#include "Topology.hh"
#include "SwitchConnection.hh"
#include "Flow.hh"
#include "Common.hh"


REGISTER_APPLICATION(Homework, {"controller",
                                "host-manager",
                                "topology",
                                "switch-manager",
                                ""})

using namespace runos;

namespace matches
{
    typedef of13::InPort in_port;
    typedef of13::EthDst eth_dst;
    typedef of13::EthSrc eth_src;
    typedef of13::EthType eth_type;
    typedef of13::IPProto ip_proto;
    typedef of13::IPv4Src ipv4_src;
    typedef of13::IPv4Dst ipv4_dst;
    typedef of13::TCPSrc tcp_src;
    typedef of13::TCPDst tcp_dst;
}

namespace actions
{
    typedef of13::OutputAction OUTPUT;
    typedef of13::SetFieldAction SET_FIELD;
}

namespace inet_types
{
    constexpr uint8_t tcp = 6;
    constexpr uint8_t udp = 17;
}


namespace eth_types
{
    constexpr uint16_t ipv4 = 0x0800;
    constexpr uint16_t ipv6 = 0x86DD;
    constexpr uint16_t arp = 0x0806;
    constexpr uint16_t vlan = 0x8100;
}


#define MATCH_FIELD(field, value) \
    try { \
        fm.add_oxm_field(new field{value}); \
    } catch (std::overflow_error) { \
        throw; \
    } catch (...) {}


std::string Homework::convert_from_net_order_to_normal_ip(const std::string& net_ip) {
    // net_ip in reversed order
    uint32_t normal_ip = IPAddress::IPv4from_string(net_ip);
    uint32_t reversed_ip = htonl(normal_ip);
    std::string ip = AppObject::uint32_t_ip_to_string(reversed_ip);

    return ip;
}


std::string Homework::convert_IPAddress_to_string(IPAddress& ip_addr) {
    // ip in normal order

    uint32_t normal_ip = ip_addr.getIPv4();
    uint32_t reversed_ip = htonl(normal_ip);
    std::string ip = AppObject::uint32_t_ip_to_string(reversed_ip);

    return ip;
}


std::string Homework::convert_ethaddr_to_string(ethaddr& ethaddr) {
    // TODO
    return std::string("");
}


bool Homework::server_ip(IPAddress& ip_addr) {
    std::string ip = convert_IPAddress_to_string(ip_addr);

    auto it = servers_flows.find(ip);
    if (it != servers_flows.end())
        return true;

    return false;
}


bool Homework::server_mac(IPAddress& ip_addr, ethaddr& mac_addr) {
    if (!server_ip(ip_addr))
        return false;

    std::string ip = convert_IPAddress_to_string(ip_addr);
    std::string mac = servers_ip_mac[ip];
    if (mac_addr == ethaddr(mac))
        return true;

    return false;
}


bool Homework::pair_compare(const std::pair<std::string, double>& first_elem,
                  const std::pair<std::string, double>& second_elem) {
  return first_elem.second < second_elem.second;
}


std::string Homework::get_balance_server() {
    std::string result = std::string("");
    std::vector< std::pair< std::string, double>> ip_prob;

    if (servers_ip_mac.empty())
        return result;

    for (const auto& it : servers_ip_mac) {
        auto server_ip = it.first;
        auto curr_flows = flows_counter[server_ip];
        auto max_flows = servers_flows[server_ip];

        if (curr_flows >= max_flows)
            continue;

        ip_prob.push_back(std::make_pair(it.first,
                                         servers_prob[it.first]));
    }

    if (ip_prob.empty())
        return result;

    std::sort(ip_prob.begin(), ip_prob.end(), Homework::pair_compare);

    double sum = 0.0;

    for (const auto& it : ip_prob) {
        sum += it.second;
        LOG(INFO) << it.first << " " << it.second;
    }

    double left = 0.0;
    double right = 0.0;

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_real_distribution<double> dist(0.0, sum);
    double n = dist(mt);

    for (const auto& it : ip_prob) {
        right += it.second;
        if (n >= left && n <= right) {
            flows_counter[it.first]++;
            return it.first;
        }

        left = right;
    }

    // Not necessary
    // If sum of all probabilities < 1
    LOG(INFO) << "If sum of all probabilities < 1";
    // Then we will be here
    result = std::get<0>(ip_prob.back());
    flows_counter[result]++;

    return result;
}


void Homework::init(Loader *loader, const Config & rootConfig) {

    LOG(INFO) << "Homework app init";

    // Read configuration
    Config config = config_cd(rootConfig, "homework");
    uint64_t switch_dpid = config_get(config, "switch_dpid", 8);
    uint64_t idle_timeout = config_get(config, "idle_timeout", 100);
    read_configuration(config);


    // Print configuration
    LOG(INFO) << "switch_dpid " << switch_dpid;
    LOG(INFO) << "idle_timeout "  << idle_timeout;
    for (const auto& server: servers_flows)
        LOG(INFO) << server.first
                  << " " << server.second
                  << " " << servers_prob[server.first];

//    subscribe_on_flow_removed(loader);
//    subscribe_on_port_changes(loader);


    // Get dependencies
    Controller* ctrl = Controller::get(loader);
    HostManager* host_manager = HostManager::get(loader);
    Topology*  topology = Topology::get(loader);
    SwitchManager* switch_manager = SwitchManager::get(loader);

    QObject::connect(ctrl, &Controller::flowRemoved,
            [&](SwitchConnectionPtr ofconnl, of13::FlowRemoved& fr) {
                this->flowRemoved(ofconnl, fr);
            });


    QObject::connect(ctrl, &Controller::portStatus,
            [&](SwitchConnectionPtr ofconn, of13::PortStatus ps) {
                this->portStatus(ofconn, ps);
            });

    // TODO Сохранять в объекте класса Loader* loader
    // А потом там, где нужно вызывать get
    // Loader всегда передадут в init
    // А может это понадобится в обработчиках сигналов

    uint8_t table_no = ctrl->reserveTable();

    LOG(INFO) << "table number-> " << static_cast<uint32_t>(table_no);

    ctrl->registerHandler("homework",
    [=](SwitchConnectionPtr connection) {
        const auto ofb_eth_type = oxm::eth_type();
        const auto ofb_eth_src = oxm::eth_src();
        const auto ofb_eth_dst = oxm::eth_dst();
        const auto ofb_ipv4_src = oxm::ipv4_src();
        const auto ofb_ipv4_dst = oxm::ipv4_dst();
        const auto ofb_ip_proto = oxm::ip_proto();
        const auto ofb_in_port = oxm::in_port();
        const auto ofb_tcp_src = oxm::tcp_src();
        const auto ofb_tcp_dst = oxm::tcp_dst();

        return [=](Packet& pkt, FlowPtr flow, Decision decision) {
            std::stringstream ss;
            auto cookie = flow->cookie();

            if (connection->dpid() != switch_dpid) {
                return decision;
            }

            auto tpkt = packet_cast<TraceablePacket>(pkt);

            LOG(INFO) << "PACKET_IN FROM SWITCH-BALANCER";
            LOG(INFO) << "IN PORT: " << tpkt.watch(ofb_in_port);

            learnHosts(host_manager);
            print_all_known_hosts();

            my_switch = switch_manager->getSwitch(connection->dpid());
            find_mac_addr_and_sw_port_for_servers(my_switch);

            print_all_known_servers();

            ethaddr src_eth;
            ethaddr dst_eth;
            IPAddress src_ip;
            IPAddress dst_ip;


            // CHECK FRAME TYPE and IP ENCAPSULATED PROTOCOL

            auto eth_type = tpkt.watch(ofb_eth_type);
            LOG(INFO) << "eth_type -> " << eth_type;
            LOG(INFO) << "eth_types::ipv4 -> " << eth_types::ipv4;
            if (eth_type != eth_types::ipv4) {
                LOG(INFO) << "Not IPv4 PacketIn";
                pkt.load(ofb_eth_type);
                return decision
                        .hard_timeout(std::chrono::seconds::zero());
            }


            auto ip_proto = tpkt.watch(ofb_ip_proto);
            LOG(INFO) << "ip_proto -> " << ip_proto;
            LOG(INFO) << "inet_types::tcp -> " << inet_types::tcp;
            if (ip_proto != inet_types::tcp) {
                LOG(INFO) << "Not TCP PacketIn";
                pkt.load(ofb_ip_proto);
                return decision
                        .hard_timeout(std::chrono::seconds::zero());
            }


            LOG(INFO) << "captured TCP packet";

            // READ SRC IP
            src_ip = IPAddress(tpkt.watch(ofb_ipv4_src));
            LOG(INFO) << "SRC_IP -> "
                      << convert_IPAddress_to_string(src_ip);

            // READ SRC MAC
            src_eth = ethaddr(tpkt.watch(ofb_eth_src));
            LOG(INFO) << "SRC_MAC -> " << src_eth;

            // READ DST IP
            dst_ip = IPAddress(tpkt.watch(ofb_ipv4_dst));
            LOG(INFO) << "DST_IP -> "
                      << convert_IPAddress_to_string(dst_ip);

            // READ DST MAC
            dst_eth = ethaddr(tpkt.watch(ofb_eth_dst));
            LOG(INFO) << "DST_MAC -> " << dst_eth;

            // READ SRC TCP
            auto tcp_src_port = tpkt.watch(ofb_tcp_src);
            LOG(INFO) << "SRC_TCP_PORT -> " << tcp_src_port;

            // READ DST TCP
            auto tcp_dst_port = tpkt.watch(ofb_tcp_dst);
            LOG(INFO) << "DST_TCP_PORT -> " << tcp_dst_port;


            // CHECK SRC IP == MY SERVERS and DST IP == MY SERVERS
            bool src_is_server = server_ip(src_ip);
            bool dst_is_server = server_ip(dst_ip);

            // SERVER <-> SERVER
            // REMOTE CLIENT <-> REMOTE CLIENT
            if (src_is_server == dst_is_server) {
                LOG(INFO) << "NOT BALANCE";
                LOG(INFO) << "SCR IP and DST IP is from Balancing Servers IP Pool";
                pkt.load(ofb_eth_type);
                pkt.load(ofb_ip_proto);
                pkt.load(ofb_ipv4_src);
                pkt.load(ofb_ipv4_dst);
                return decision
                        .hard_timeout(std::chrono::seconds::zero());
            }


            // SERVER -> REMOTE CLIENT
            if (src_is_server and not dst_is_server) {
                LOG(INFO) << "NOT BALANCE";
                LOG(INFO) << "Server open TCP session with Remote Host";
                // Make two rules
                ss.str(std::string());
                ss.clear();
                ss << dst_eth;
                auto switch_id = get_host_switch_id(ss.str());

                auto route = topology
                             ->computeRoute(connection->dpid(), switch_id);

//=======================CREATE FLOW MOD SERVER->CLIENT========================
{
                // ADD INFO
                of13::FlowMod fm;
                fm.command(of13::OFPFC_ADD);
                fm.table_id(table_no);
                fm.idle_timeout(idle_timeout);
                fm.hard_timeout(idle_timeout);
                fm.priority(1);

                // ADD MATCH
                // process L4
                MATCH_FIELD(matches::tcp_src, tcp_src_port)
                MATCH_FIELD(matches::tcp_dst, tcp_dst_port)
                MATCH_FIELD(matches::ip_proto, inet_types::tcp)

                // process L3
                MATCH_FIELD(matches::ipv4_src, IPAddress(htonl(src_ip.getIPv4())))
                MATCH_FIELD(matches::ipv4_dst, IPAddress(htonl(dst_ip.getIPv4())))

                // process L2, L1
                ss.str(std::string());
                ss.clear();
                ss << src_eth;
                MATCH_FIELD(matches::eth_src, EthAddress(ss.str()))
                ss.str(std::string());
                ss.clear();
                ss << dst_eth;
                MATCH_FIELD(matches::eth_dst, EthAddress(ss.str()))
                MATCH_FIELD(matches::eth_type, eth_types::ipv4)

                // ADD ACTIONs
                of13::ApplyActions applyActions;

                // ADD OUTPUT ACTION
                uint32_t out_port = route[0].port;
                actions::OUTPUT output_action(out_port, 0);
                applyActions.add_action(output_action);

                // Add all actions to flow
                fm.add_instruction(applyActions);

                // Send flow to switch
                connection->send(fm);
}

//=======================CREATE FLOW MOD CLIENT->SERVER========================
{
                // ADD INFO
                of13::FlowMod fm;
                fm.command(of13::OFPFC_ADD);
                fm.table_id(table_no);
                fm.idle_timeout(idle_timeout);
                fm.hard_timeout(idle_timeout);
                fm.priority(1);

                // ADD MATCH
                // process L4
                MATCH_FIELD(matches::tcp_src, tcp_dst_port)
                MATCH_FIELD(matches::tcp_dst, tcp_src_port)
                MATCH_FIELD(matches::ip_proto, inet_types::tcp)

                // process L3
                MATCH_FIELD(matches::ipv4_src, IPAddress(htonl(dst_ip.getIPv4())))
                MATCH_FIELD(matches::ipv4_dst, IPAddress(htonl(src_ip.getIPv4())))

                // process L2, L1
                ss.str(std::string());
                ss.clear();
                ss << dst_eth;
                MATCH_FIELD(matches::eth_src, EthAddress(ss.str()))
                ss.str(std::string());
                ss.clear();
                ss << src_eth;
                MATCH_FIELD(matches::eth_dst, EthAddress(ss.str()))
                MATCH_FIELD(matches::eth_type, eth_types::ipv4)

                // ADD ACTIONs
                of13::ApplyActions applyActions;

                // ADD OUTPUT ACTION
                uint32_t out_port = uint32_t(tpkt.watch(ofb_in_port));
                actions::OUTPUT output_action(out_port, 0);
                applyActions.add_action(output_action);

                // Add all actions to flow
                fm.add_instruction(applyActions);

                // Send flow to switch
                connection->send(fm);

}

//======================SEND PACKET_OUT WITH FIRST PACKET=======================
{
                uint32_t out_port = route[0].port;
                return decision
                        .unicast(out_port)
                        .hard_timeout(std::chrono::seconds::zero())
                        .idle_timeout(std::chrono::seconds::zero())
                        .drop()
                        .return_();
}
            }


//==============================BALANCE========================================
//========= NOW THERE ARE PACKETs TO MY SERVERS ONLY FROM REMOTE CLIENT========

//            // CHECK PACKET HAS RIGHT DST MAC
//            if (!server_mac(dst_ip, dst_eth)) {
//                LOG(INFO) << "TCP Packet NOT with Balancing Servers MAC";
//                pkt.load(ofb_eth_type);
//                pkt.load(ofb_eth_dst);
//                pkt.load(ofb_ip_proto);
//                pkt.load(ofb_ipv4_src);
//                pkt.load(ofb_ipv4_dst);
//                return decision
//                        .hard_timeout(std::chrono::seconds::zero());
//            }


            // Choose server by algorithm
            // Modify Counter for this server
            // If empty string is returned then drop packet
            // because servers are busy
            std::string real_ip = get_balance_server();

            LOG(INFO) << "REAL IP ->" << real_ip;
            if (real_ip == std::string("")) {
                LOG(INFO) << "NOT BALANCE";
                return decision
                        .idle_timeout(std::chrono::seconds::zero())
                        .hard_timeout(std::chrono::seconds::zero())
                        .drop()
                        .return_();
            }

            std::string real_mac = servers_ip_mac[real_ip];

            LOG(INFO) << "BALANCE TCP Session";

            // Save flow TCP session
            save_tcp_session(cookie, real_ip);

//=======================CREATE FLOW MOD CLIENT->SERVER========================
{
            // ADD INFO
            of13::FlowMod fm;
            fm.command(of13::OFPFC_ADD);
            fm.table_id(table_no);
            fm.cookie(cookie);
            fm.idle_timeout(idle_timeout);
            fm.hard_timeout(idle_timeout);
            fm.priority(1);
            fm.flags(of13::OFPFF_SEND_FLOW_REM);

            // ADD MATCH
            // process L4
            MATCH_FIELD(matches::tcp_src, tcp_src_port)
            MATCH_FIELD(matches::tcp_dst, tcp_dst_port)
            MATCH_FIELD(matches::ip_proto, inet_types::tcp)

            // process L3
            MATCH_FIELD(matches::ipv4_src, IPAddress(htonl(src_ip.getIPv4())))
            MATCH_FIELD(matches::ipv4_dst, IPAddress(htonl(dst_ip.getIPv4())))

            // process L2, L1
            ss.str(std::string());
            ss.clear();
            ss << src_eth;
            MATCH_FIELD(matches::eth_src, EthAddress(ss.str()))
            ss.str(std::string());
            ss.clear();
            ss << dst_eth;
            MATCH_FIELD(matches::eth_dst, EthAddress(ss.str()))
            MATCH_FIELD(matches::eth_type, eth_types::ipv4)

            // ADD ACTIONs
            of13::ApplyActions applyActions;
            // Change dst DST IP
            of13::OXMTLV *field = new matches::ipv4_dst{real_ip};
            auto act = new actions::SET_FIELD{field};
            applyActions.add_action(act);

            // Change dst DST MAC
            field = new matches::eth_dst{real_mac};
            act = new actions::SET_FIELD{field};
            applyActions.add_action(act);

            // ADD OUTPUT ACTION
            uint32_t out_port = server_ip_switch_port[real_ip];
            actions::OUTPUT output_action(out_port, 0);
            applyActions.add_action(output_action);

            // Add all actions to flow
            fm.add_instruction(applyActions);

            // Send flow to switch
            connection->send(fm);
}

//=======================CREATE FLOW MOD SERVER->CLIENT========================
{
            // ADD INFO
            of13::FlowMod fm;
            fm.command(of13::OFPFC_ADD);
            fm.table_id(table_no);
            fm.cookie(cookie);
            fm.idle_timeout(idle_timeout);
            fm.hard_timeout(idle_timeout);
            fm.priority(1);

            // ADD MATCH
            // process L4
            MATCH_FIELD(matches::tcp_src, tcp_dst_port)
            MATCH_FIELD(matches::tcp_dst, tcp_src_port)
            MATCH_FIELD(matches::ip_proto, inet_types::tcp)

            // process L3
            MATCH_FIELD(matches::ipv4_src, IPAddress(real_ip))
            MATCH_FIELD(matches::ipv4_dst, IPAddress(htonl(src_ip.getIPv4())))

            // process L2, L1
            MATCH_FIELD(matches::eth_src, EthAddress(real_mac))
            ss.str(std::string());
            ss.clear();
            ss << src_eth;
            MATCH_FIELD(matches::eth_dst, EthAddress(ss.str()))
            MATCH_FIELD(matches::eth_type, eth_types::ipv4)

            // ADD ACTIONs
            of13::ApplyActions applyActions;
            // Change SRC IP
            of13::OXMTLV *field =
                    new matches::ipv4_src{convert_IPAddress_to_string(dst_ip)};
            auto act = new actions::SET_FIELD{field};
            applyActions.add_action(act);

            // Change SRC MAC
            ss.str(std::string());
            ss.clear();
            ss << dst_eth;
            field = new matches::eth_src{EthAddress(ss.str())};
            act = new actions::SET_FIELD{field};
            applyActions.add_action(act);

            // ADD OUTPUT ACTION
            uint32_t out_port = uint32_t(tpkt.watch(ofb_in_port));
            actions::OUTPUT output_action(out_port, 0);
            applyActions.add_action(output_action);

            // Add all actions to flow
            fm.add_instruction(applyActions);

            // Send flow to switch
            connection->send(fm);
}

//======================SEND PACKET_OUT WITH FIRST PACKET=======================
{

            uint32_t out_port = server_ip_switch_port[real_ip];
            return decision
                    .unicast(out_port)
                    .hard_timeout(std::chrono::seconds::zero())
                    .idle_timeout(std::chrono::seconds::zero())
                    .drop()
                    .return_();
}
        };
    });
}

void Homework::read_configuration(const Config& config) {
    const auto& servers = config.at("servers").array_items();

    for (const auto& server : servers) {
        auto server_info = server.object_items();
        auto ip_it = server_info.find("ip");
        auto flow_it = server_info.find("max_flows");
        auto prob_it = server_info.find("prob");

        if ( ip_it == server_info.end() ) {
            LOG(INFO) << "Error while read homework config" <<
                         "ip addres doesn't exist";
        } else if ( flow_it == server_info.end() ) {
            LOG(INFO) << "Error while read homework config" <<
                         "max_flows doesn't exist";
        } else if ( prob_it == server_info.end() ) {
            LOG(INFO) << "Error while read homework config" <<
                         "server choose probability doesn't exist";
        } else {
            servers_flows[ip_it->second.string_value()] =
                    static_cast<uint64_t>(flow_it->second.int_value());
            flows_counter[ip_it->second.string_value()] =
                    static_cast<uint64_t>(0);
            servers_prob[ip_it->second.string_value()] =
                    static_cast<double>(prob_it->second.number_value());
        }
    }
}


void Homework::flowRemoved(SwitchConnectionPtr ofconnl, of13::FlowRemoved& fr) {

    uint64_t cookie = fr.cookie();
    auto it = cookie_server.find(cookie);

    if (it == cookie_server.end())
        return;

    LOG(INFO) << "Rules with cookie: "
              << std::hex
              << cookie
              << " was removed";

    del_tcp_session(cookie);
}

void Homework::subscribe_on_flow_removed(Loader* loader) {
    Controller* ctrl = Controller::get(loader);
    connect(ctrl, &Controller::flowRemoved,
            this, &Homework::flowRemoved);
}



void Homework::portStatus(SwitchConnectionPtr ofconn, of13::PortStatus ps) {

    // В этом методе ничего не нужно делать
    // На самом деле удаление порта - вызовет также слот и в SwitchManager'е,
    // который вызовет соотв метод у  свитча с соотв dpid'ом Switch'а. Свитч удалит порт у себя.
    // Далее моё приложение должно понять, что соотв сервер недоступен.
    // Это можно узнать у самого свитча. В хендлере в самом начале я узнаю, какие у
    // серверов маки и ip. Там же узнаю и доступность серверов. Если порта с самого начала нет,
    // то об отсутствии сервера мне скажет HostManager. Если порт упал в процессе работы, то
    // Мне об этом может сказать только свитч, так как HostManager будет помнить старую информацию

    // А чисткой кук и изменением счетчиков по таймауту займется как обычно
    // del_tcp_session


    of13::Port port = ps.desc();
    uint32_t port_no = port.port_no();

    if (my_switch == nullptr)
        return;

    if (ofconn->dpid() != my_switch->id())
        return;

    switch (ps.reason()) {
        case of13::OFPPR_ADD: {
            LOG(INFO) << "Port Status Changes: "
                  << "Port #"
                  << port_no
                  << " on switch "
                  << my_switch->idstr()
                  << " was added";
            break;
        }
        case of13::OFPPR_DELETE: {
            LOG(INFO) << "Port Status Changes: "
                      << "Port #"
                      << port_no
                      << " on switch "
                      << my_switch->idstr()
                      << " was deleted";
            break;
        }
        case of13::OFPPR_MODIFY: {
            break;
        }
    }
}

void Homework::subscribe_on_port_changes(Loader* loader) {
    Controller* ctrl = Controller::get(loader);
    connect(ctrl, &Controller::portStatus,
            this, &Homework::portStatus);
}


void Homework::print_all_known_hosts() {
    // Print all known hosts mac and ip

    LOG(INFO) << "All known hosts";
    for (const auto& it : hosts) {

        // Attention. Host ip in reversed form
        std::string host_ip =
                convert_from_net_order_to_normal_ip(it.second->ip());
        std::string host_mac =it.second->mac();
        uint32_t switch_port = it.second->switchPort();
        LOG(INFO) << host_ip << " "
                  << host_mac << " "
                  << switch_port;
    }
}


void Homework::print_all_known_servers() {
    // Print known servers

    LOG(INFO) << "All known servers";
    for (const auto& it : servers_ip_mac) {
        LOG(INFO) << it.first << " "
                  << it.second;
    }
}


void Homework::learnHosts(HostManager * host_manager) {
    if (host_manager == nullptr)
        hosts.clear();

    hosts = host_manager->hosts();
}


uint64_t Homework::get_host_switch_id(const std::string& mac) {
    auto it = hosts.find(mac);
    if (it != hosts.end())
        return it->second->switchID();

    return 0;
}


void Homework::save_tcp_session(const uint64_t& cookie, const std::string&  ip) {
    LOG(INFO) << "Save TCP session with cookie: "
              << std::hex
              << cookie;
    cookie_server[cookie] = ip;
}

void Homework::del_tcp_session(const uint64_t& cookie) {
    auto it = cookie_server.find(cookie);
    if (it == cookie_server.end())
        return;

    LOG(INFO) << "Delete TCP session with cookie: "
              << std::hex
              << cookie;
    auto ip = it->second;
    cookie_server.erase(cookie);

    if (flows_counter[ip] == 0) {
        LOG(INFO) << "Attention. May be error: fows_counter[ip] == 0 before subtraction";
        return;
    }
    flows_counter[ip]--;
}


void Homework::find_mac_addr_and_sw_port_for_servers(Switch* sw) {
    // Find mac for my servers by server ip
    // Learn alive servers and servers which
    // ip
    // controller know

    // sw is my switch
    // Хосты определяются всегда по маку. - так сделано в HostManager
    // Некоторые хосты могут стать недоступными, если упал порт на другом конце вирт провода
    // (т.е. у коммутатора).
    // HostManager об это не узнает. Но о падении порта узнает коммутатор.
    // Если порт упал, то у коммутатора удалится порт.
    // Вот и нужно проверить, что у моего сервера, которого
    // я достал из hosts, порт коммутатора, на котором он висит,
    // все еще жив.

    // Более весомый аргумент. Сервер недоступен, если пути от
    // коммутаторы до него не существует

    auto ports = sw->ports();
    servers_ip_mac.clear();

    LOG(INFO) << "Ports on my switch";
    for (auto& port : ports)
        LOG(INFO) << port.port_no();

    for (const auto& server_it : servers_flows) {
        std::string server_ip = server_it.first;
        for (const auto& host_it : hosts) {
            Host * host = host_it.second;

            // Attention. Host ip in reversed form
            std::string host_ip =
                    convert_from_net_order_to_normal_ip(host->ip());

            if (host_ip == server_ip) {
                bool alive = false;
                uint32_t port = host->switchPort();
                std::string mac = host->mac();

                // Check port alive
                for (auto& p : ports) {
                    if (p.port_no() == port) {
                        alive = true;
                        break;
                    }
                }

                if (not alive)
                    continue;

                servers_ip_mac[server_ip] = mac;
                server_ip_switch_port[server_ip] = port;
                break;
            }
        }
    }
}
