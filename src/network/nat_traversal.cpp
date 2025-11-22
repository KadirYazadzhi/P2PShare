#include "network/nat_traversal.hpp"
#include <cstring> // For strncpy

NatTraversal::NatTraversal() {
    // Initialize miniupnpc
    upnp_dev_ = nullptr;
    memset(&upnp_urls_, 0, sizeof(upnp_urls_));
    memset(&upnp_data_, 0, sizeof(upnp_data_));
    memset(lan_address_, 0, sizeof(lan_address_));
}

NatTraversal::~NatTraversal() {
    // Clean up miniupnpc resources
    if (upnp_dev_) {
        freeUPNPDevlist(upnp_dev_);
        upnp_dev_ = nullptr;
    }
    FreeUPNPUrls(&upnp_urls_);
}

bool NatTraversal::discover_devices() {
    const char* multicast_if = nullptr;
    const char* minixml_buf = nullptr;
    int error = 0;

    std::cout << "Discovering UPnP devices..." << std::endl;
    unsigned char ttl = 2; // Default TTL as advised by UDA 1.1
    upnp_dev_ = upnpDiscover(2000, multicast_if, minixml_buf, 0, 0, ttl, &error);

    if (upnp_dev_) {
        std::cout << "UPnP device found." << std::endl;
        char wan_address[64]; // Buffer for WAN address
        if (UPNP_GetValidIGD(upnp_dev_, &upnp_urls_, &upnp_data_, lan_address_, sizeof(lan_address_), wan_address, sizeof(wan_address)) == 1) {
            std::cout << "Valid IGD found. Local IP: " << lan_address_ << std::endl;
            return true;
        } else {
            std::cerr << "No valid IGD found." << std::endl;
            freeUPNPDevlist(upnp_dev_);
            upnp_dev_ = nullptr;
            return false;
        }
    } else {
        std::cerr << "No UPnP devices found. Error: " << error << std::endl;
        return false;
    }
}

std::string NatTraversal::get_external_ip() {
    if (!upnp_dev_ || !upnp_urls_.controlURL[0]) {
        std::cerr << "UPnP device not discovered or not initialized." << std::endl;
        return "";
    }

    char external_ip[16];
    if (UPNP_GetExternalIPAddress(upnp_urls_.controlURL, upnp_data_.first.servicetype, external_ip) == UPNPCOMMAND_SUCCESS) {
        std::cout << "External IP Address: " << external_ip << std::endl;
        return external_ip;
    } else {
        std::cerr << "Failed to get external IP address." << std::endl;
        return "";
    }
}

bool NatTraversal::add_port_mapping(int internal_port, int external_port, const std::string& description, const std::string& protocol) {
    if (!upnp_dev_ || !upnp_urls_.controlURL[0]) {
        std::cerr << "UPnP device not discovered or not initialized." << std::endl;
        return false;
    }

    char external_port_str[16];
    char internal_port_str[16];
    snprintf(external_port_str, sizeof(external_port_str), "%d", external_port);
    snprintf(internal_port_str, sizeof(internal_port_str), "%d", internal_port);

    std::cout << "Adding port mapping: external " << external_port << " -> internal " << lan_address_ << ":" << internal_port << " (" << protocol << ")" << std::endl;

    int r = UPNP_AddPortMapping(upnp_urls_.controlURL, upnp_data_.first.servicetype,
                                external_port_str, internal_port_str, lan_address_,
                                description.c_str(), protocol.c_str(), nullptr, "0"); // "0" for infinite lease time

    if (r == UPNPCOMMAND_SUCCESS) {
        std::cout << "Port mapping added successfully." << std::endl;
        return true;
    } else {
        std::cerr << "Failed to add port mapping. Error: " << r << " (" << strupnperror(r) << ")" << std::endl;
        return false;
    }
}

bool NatTraversal::remove_port_mapping(int external_port, const std::string& protocol) {
    if (!upnp_dev_ || !upnp_urls_.controlURL[0]) {
        std::cerr << "UPnP device not discovered or not initialized." << std::endl;
        return false;
    }

    char external_port_str[16];
    snprintf(external_port_str, sizeof(external_port_str), "%d", external_port);

    std::cout << "Removing port mapping: external " << external_port << " (" << protocol << ")" << std::endl;

    int r = UPNP_DeletePortMapping(upnp_urls_.controlURL, upnp_data_.first.servicetype,
                                   external_port_str, protocol.c_str(), nullptr);

    if (r == UPNPCOMMAND_SUCCESS) {
        std::cout << "Port mapping removed successfully." << std::endl;
        return true;
    } else {
        std::cerr << "Failed to remove port mapping. Error: " << r << " (" << strupnperror(r) << ")" << std::endl;
        return false;
    }
}
