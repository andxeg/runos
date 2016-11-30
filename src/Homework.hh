/*
 * App: Load-Balancer
 * Protocol: TCP
 * Algorithm: Weighted random
 * Topology: 3
 * author: Andrew Chupakhin
 */


#pragma once
#include "Application.hh"
#include "Loader.hh"
#include "HostManager.hh"
#include <unordered_map>
#include "types/ethaddr.hh"
#include "Switch.hh"
#include "Flow.hh"
#include "Topology.hh"

// Servers from configuration file
// "ip" : "number_of__max_flows"
std::unordered_map<std::string, uint64_t> servers_flows;


// Counter for each server. Counter must be less or
// equal then max_flows for each server
// "ip" : "number_of_current_flows"
std::unordered_map<std::string, uint64_t> flows_counter;

// Probability of server choosing
// Need for balanced algorithm
std::unordered_map<std::string, double> servers_prob;

// Alive server and server with ip in current moment
// "ip" : "mac"
// The MAIN VARIABLE WHICH KEEP ALL ALIVE SERVERS
std::unordered_map<std::string, std::string> servers_ip_mac;

// Server and corresponding switch port
// "ip" : switch port
std::unordered_map<std::string, uint32_t> server_ip_switch_port;

// All alive hosts and host with ip
// "mac" : host
std::unordered_map<std::string, Host*> hosts;


// Current TCP sessions
std::unordered_map<uint64_t, std::string> cookie_server;


class Homework : public Application {
SIMPLE_APPLICATION(Homework, "homework")
public:
    void init(Loader* loader, const Config& rootConfig) override;
private:
    void read_configuration(const Config& config);

    void subscribe_on_flow_removed(Loader* loader);
    void subscribe_on_port_changes(Loader* loader);

    static std::string convert_from_net_order_to_normal_ip(const std::string& net_ip);
    static std::string convert_IPAddress_to_string(IPAddress& ip);
    static std::string convert_ethaddr_to_string(ethaddr& ethaddr);

    static bool server_ip(IPAddress& ip_addr);
    static bool server_mac(IPAddress& ip_addr, ethaddr& mac_addr);
    static bool pair_compare(const std::pair<std::string, double>& first_elem,
                             const std::pair<std::string, double>& second_elem);
    static std::string get_balance_server();

    // print function
    static void print_all_known_hosts();
    static void print_all_known_servers();

    static uint64_t get_host_switch_id(const std::string& mac);
    static void learnHosts(HostManager * host_manager);
    static void find_mac_addr_and_sw_port_for_servers(Switch* sw);

    static void save_tcp_session(const uint64_t& cookie, const std::string& ip);
    static void del_tcp_session(const uint64_t& cookie);

protected slots:
//    void flowRemoved(SwitchConnectionPtr ofconnl, uint64_t fr_cookie);
    void flowRemoved(SwitchConnectionPtr ofconnl, of13::FlowRemoved& fr);
    void portStatus(SwitchConnectionPtr ofconn, of13::PortStatus ps);


private:
    Switch* my_switch = nullptr;
};

// Print OF13 rules
// sudo ovs-ofctl -O OpenFlow13 dump-flows <switch_name>

// Start HTTP server in mininet host
// h1 python -m SimpleHTTPServer 80 &
// h2 wget -O - h1
// h1 kill %python
