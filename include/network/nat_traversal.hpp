#ifndef P2P_NAT_TRAVERSAL_HPP
#define P2P_NAT_TRAVERSAL_HPP

#include <string>
#include <vector>
#include <memory>
#include <iostream>

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

private:
    struct UPNPDev* upnp_dev_ = nullptr;
    struct UPNPUrls upnp_urls_;
    struct IGDdatas upnp_data_;
    char lan_address_[64];
};

#endif // P2P_NAT_TRAVERSAL_HPP
