# bob13-csa
![image](https://github.com/user-attachments/assets/384a503a-622d-4de9-aee2-fe790297a106)

![Uploading image.png…]()

# Beacon Frame Tagged Parameter 조작 실습

본 문서는 IEEE 802.11 무선 네트워크 환경에서 **Beacon Frame을 캡처하고, Tagged Parameter를 수정하여 재전송하는 코드의 동작 원리**를 설명합니다.  
해당 코드는 보안 네트워크 학습 과정에서 **802.11 프레임 구조, Radiotap 헤더, ARP가 아닌 무선 관리 프레임 처리 방식**을 이해하기 위해 작성되었습니다.

---

## 1. 개요

이 프로그램은 특정 AP에서 송출되는 **Beacon Frame**을 실시간으로 캡처한 뒤,

- Radiotap 헤더를 분석하고
- 802.11 Management Beacon Frame인지 확인하며
- Beacon의 Tagged Parameter 영역에 **새로운 Tag를 삽입**
- 수정된 패킷을 다시 무선 인터페이스로 전송

하는 과정을 반복 수행합니다.

이를 통해 무선 관리 프레임이 실제로 어떻게 구성되고,  
**패킷 단위에서 어떤 필드를 조작할 수 있는지**를 직접 확인하는 것이 목적입니다.

---

## 2. 사용 기술 및 환경

- **언어**: C++
- **라이브러리**: libpcap
- **네트워크 계층**: IEEE 802.11 (Management Frame)
- **패킷 처리 방식**: Raw Packet Capture & Injection
- **운영체제**: Linux (모니터 모드 필요)

---

## 3. 프로그램 실행 방식

```bash
./program <interface> <AP MAC> [Station MAC]
