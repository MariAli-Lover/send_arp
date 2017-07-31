send_arp
========
An Simple ARP table overwriter
------------------------------
###사용법과 원리
1. ./send_arp <interface> <sender ip> <target ip>
2. sender ip로 ARP Request를 하여 MAC Address를 알아낸다.
3. target ip에 대해서도 마찬가지의 작업을 시행한다.
4. 2, 3에서 얻은 정보를 바탕으로 지속적으로 ARP Reply를 sender ip로 보낸다.
###주의할 점
sleep() 등의 함수를 일부러 사용하지 않아 ARP Reply를 매우 짧은 주기로 보내기 때문에 네트워크에 큰 부하를 일으킬 수 있습니다. 프로그램을 테스트하신다면 이 사실을 명시해두시기를 바랍니다.
