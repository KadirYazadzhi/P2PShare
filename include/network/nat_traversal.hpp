#ifndef P2P_NAT_TRAVERSAL_HPP
#define P2P_NAT_TRAVERSAL_HPP

#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <optional> // Added for std::optional
#include <asio/ip/udp.hpp> // Added for udp::endpoint
#include <asio/io_context.hpp> // Added for asio::io_context

// miniupnpc includes
#include "upnpcommands.h"
#include "upnperrors.h"
#include "miniupnpc.h"
#include "portlistingparse.h"

class NatTraversal {
public:
    NatTraversal();
    ~NatTraversal();

    bool discover_devices();
    std::string get_external_ip();
    bool add_port_mapping(int internal_port, int external_port, const std::string& description, const std::string& protocol = "TCP");
    bool remove_port_mapping(int external_port, const std::string& protocol = "TCP");

    // STUN related functionality (placeholder for now)
    std::optional<asio::ip::udp::endpoint> perform_stun_request(asio::io_context& io_context, const asio::ip::udp::endpoint& local_endpoint);

private:
    struct UPNPDev* upnp_dev_ = nullptr;
    struct UPNPUrls upnp_urls_;
    struct IGDdatas upnp_data_;
    char lan_address_[64];
};

#endif // P2P_NAT_TRAVERSAL_HPP