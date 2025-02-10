#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <pcap.h>
#include <unistd.h>
#include "headers.h"

#define MANAGEMENT_TYPE 0     // Management frame의 type은 0
#define BEACON_SUBTYPE 8      // Beacon frame의 subtype은 8

// Tagged Parameter 파싱 함수
TaggedParameter parse_tagged_parameter(const uint8_t* data) {
    TaggedParameter param;
    param.tag_number = data[0];
    param.length = data[1];
    param.value = data + 2;
    return param;
}

// Radiotap Header에서 FCS 플래그 제거하는 함수
void remove_fcs_flag(std::vector<uint8_t>& packet) {
    if (packet.size() < sizeof(RadiotapHeader)) {
        std::cerr << "Packet too small to contain Radiotap Header!" << std::endl;
        return;
    }

    // Radiotap Header 포인터 설정
    RadiotapHeader* radiotap = reinterpret_cast<RadiotapHeader*>(packet.data());

    // 현재 Flags 값을 가져옴
    uint8_t* flags_ptr = packet.data() + sizeof(RadiotapHeader) - 1; // Flags 위치

    // FCS 포함 플래그(0x10) 확인
    if (*flags_ptr & 0x10) {
        std::cout << "FCS Flag is set, removing it..." << std::endl;
        
        // FCS 플래그 비활성화
        *flags_ptr &= ~0x10;

        // 패킷에서 마지막 4바이트(FCS) 제거
        if (packet.size() > 4) {
            packet.resize(packet.size() - 4);
            std::cout << "FCS removed from the packet." << std::endl;
        }
    } else {
        std::cout << "FCS Flag is NOT set, no change needed." << std::endl;
    }
}

// 전체 Tag 파라미터가 오름차순을 유지하도록 새 버퍼를 반환
std::vector<uint8_t> insert_new_tag(const uint8_t* tagged_params, size_t params_len) {
    const uint8_t new_tag_number = 0x25;
    const uint8_t new_tag_length = 0x03;
    const uint8_t new_tag_value[3] = { 0x01, 0x0B, 0x03 };

    std::vector<uint8_t> updated;
    bool inserted = false;
    bool tag_exists = false;
    size_t offset = 0;

    while (offset < params_len) {
        if (offset + 2 > params_len) break;
        uint8_t curr_tag = tagged_params[offset];
        uint8_t curr_len = tagged_params[offset + 1];
        // 이미 0x25 태그가 존재하는 경우
        if (curr_tag == new_tag_number) {
            tag_exists = true;  // 존재 여부 표시
        }
        
        if (!inserted && !tag_exists && curr_tag > new_tag_number) {
            std::cout << "new_tag in here " << std::endl;
            // 현재 태그 정보 출력
        std::cout << "Tag Number: 37, Length: 3" << std::endl;
            updated.push_back(new_tag_number);
            updated.push_back(new_tag_length);
            updated.insert(updated.end(), new_tag_value, new_tag_value + new_tag_length);
            inserted = true;
        }

        updated.push_back(curr_tag);
        updated.push_back(curr_len);
        if (offset + 2 + curr_len > params_len) break;
        updated.insert(updated.end(), tagged_params + offset + 2, tagged_params + offset + 2 + curr_len);
        offset += 2 + curr_len;
        // 현재 태그 정보 출력
        std::cout << "Tag Number: " << static_cast<int>(curr_tag)
                << ", Length: " << static_cast<int>(curr_len) << std::endl;
    }

    if (!inserted && !tag_exists) {
        updated.push_back(new_tag_number);
        updated.push_back(new_tag_length);
        updated.insert(updated.end(), new_tag_value, new_tag_value + new_tag_length);
    }

    return updated;
}

void send_modified_packet(pcap_t* pcap, const u_char* packet, size_t length) {
    if (pcap_sendpacket(pcap, packet, length) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
    } else {
        printf("Modified packet sent successfully.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <interface> <AP MAC> [Station MAC]\n", argv[0]);
        return -1;
    }

    char* interface = argv[1];
    MacAddress ap_mac = parse_mac(argv[2]);
    MacAddress station_mac{};

    if (argc == 4) {
        station_mac = parse_mac(argv[3]);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) continue;

        const RadiotapHeader* radiotap = reinterpret_cast<const RadiotapHeader*>(packet);
        const Frame80211* frame = reinterpret_cast<const Frame80211*>(packet + radiotap->length);

        if (!(frame->type == MANAGEMENT_TYPE && frame->subtype == BEACON_SUBTYPE)) {
            continue;
        }

        if (memcmp(frame->address3.addr, ap_mac.addr, 6) != 0) {
            continue;
        }

        if (argc == 4 && memcmp(frame->address1.addr, station_mac.addr, 6) != 0) {
            continue;
        }        

        const uint8_t* tagged_params = reinterpret_cast<const uint8_t*>(frame) + sizeof(Frame80211);
        size_t fixed_para_len = 12;
        size_t tagged_len = header->caplen - (radiotap->length + sizeof(Frame80211) + fixed_para_len);

        // Start Insert
        std::vector<uint8_t> updated_params = insert_new_tag(tagged_params + fixed_para_len, tagged_len);
        std::vector<uint8_t> modified_packet(packet, packet + header->caplen);

        // RadiotapHeader* mod_radiotap = reinterpret_cast<RadiotapHeader*>(modified_packet.data());
        // mod_radiotap->length -= 8;

        size_t tag_offset = radiotap->length + sizeof(Frame80211) + fixed_para_len;
        modified_packet.erase(modified_packet.begin() + tag_offset, modified_packet.end());
        modified_packet.insert(modified_packet.end(), updated_params.begin(), updated_params.end());

        if (argc == 4){
            Frame80211* mod_frame = reinterpret_cast<Frame80211*>(modified_packet.data() + radiotap->length);
            memcpy(mod_frame->address1.addr, station_mac.addr, 6);  // Destination MAC 변경
        }
        remove_fcs_flag(modified_packet);
        send_modified_packet(pcap, modified_packet.data(), modified_packet.size());
        usleep(10000);
    }

    pcap_close(pcap);
    return 0;
}
