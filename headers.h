#ifndef MAC_ADDRESS_H
#define MAC_ADDRESS_H

#include <cstdint>
#include <vector>  // 추가해야 함

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <string>
#pragma once


#pragma pack(push, 1) // 1-byte alignment

// 맥 주소 구조체
struct MacAddress {
    uint8_t addr[6];
};

// MAC 주소를 생성하는 함수
inline MacAddress make_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {
    MacAddress mac = {{a, b, c, d, e, f}};
    return mac;
}

// Radiotap Header structure
struct RadiotapHeader {
    uint8_t version;    // Always 0
    uint8_t pad;
    uint16_t length;    // Total length of the radiotap header
    uint32_t present;   // Bitmask indicating available fields
};

struct Frame80211 {
    uint8_t version : 2;
    uint8_t type : 2;
    uint8_t subtype : 4;
    uint8_t flags = 0;
    uint16_t duration = 0;
    MacAddress address1;
    MacAddress address2;
    MacAddress address3;
    uint16_t sequence_control = 0;
};

// Tagged Parameter structure
struct TaggedParameter {
    uint8_t tag_number;
    uint8_t length;
    const uint8_t* value;
};

// Beacon Packet structure
struct BeaconPacket {
    MacAddress bssid;      // BSSID
    int beacon_count;      // Beacon count
    int data_count;        // Data count
    std::string encryption;     // Encryption type
    std::string essid;          // ESSID
    int power;             // Signal strength
};

#pragma pack(pop)


// MAC 주소 출력 함수
inline void print_mac(const MacAddress& mac) {
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac.addr[i]);
        if (i < 5) std::cout << ":";
    }
}

// 문자열을 MAC 주소로 변환하는 함수
MacAddress parse_mac(const char* mac_str) {
    MacAddress mac{};
    int values[6];

    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
               &values[0], &values[1], &values[2], 
               &values[3], &values[4], &values[5]) != 6) {
        std::cerr << "Invalid MAC address format: " << mac_str << std::endl;
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 6; i++) {
        mac.addr[i] = static_cast<uint8_t>(values[i]);
    }
    return mac;
}

#endif
