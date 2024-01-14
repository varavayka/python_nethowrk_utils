from  scapy.all import ARP, Ether, ls, sendp, send,srp1,srp,sr, TCP, IP, UDP, ICMP,sr1, RandShort
import argparse
def scan(ip):

    
   arp_request = ARP(pdst=ip)
   broadcast  = Ether(dst="ff:ff:ff:ff:ff:ff")
   answered_list, unanswered_list = srp(broadcast / arp_request, timeout=1, verbose=False)

   result_list = []
   for i in answered_list:
      result_dict = dict()
      result_dict['ip'] = i[1].psrc
      result_dict['mac'] = i[1].hwsrc

      result_list.append(result_dict) 

   return result_list

def scan_result(host_list):
   counts = 1
   delimeter = 120 * '_'
   print(f'{delimeter}\n\xa0\xa0IP\t\t\t\t\tMAC\t\t\t\tПорт\t\t\t\tFLAGS\n{delimeter}')

   for host in host_list:
      table_hosts = f"\n{counts}.\xa0{host['ip']}\t\t\t{host['mac']}\t\t\t{host['port']}\t\t\t{ 'Порт открыт' if host['flags']== 'SA' else 'Порт закрыт'}"
      counts += 1
      print(table_hosts)

def get_cli_arguments():
   parser = argparse.ArgumentParser()
   parser.add_argument('-t', '--target', dest='target', help='Target IP / IP range')
   return parser.parse_args().target



def check_tcp_port(ports, hosts):
   result_list = []
   i = 0
   tcp_package = TCP(dport=ports,flags='S')
   
   print('Сканирование портов....')
   
   for host in hosts:
      ip_address = host['ip']
      ip_package = IP(dst=ip_address)
      syn_package = ip_package / tcp_package
      answered_list, unanswered_list = sr(syn_package, timeout=0.5, verbose=False)

      while len(answered_list) > i:
         answer_data = answered_list[i]
         scan_result = {
            'port': (answer_data.query).dport,
            'ip': (answer_data.answer).src,
            'flags': (answer_data.answer)[1].flags,
            'mac': host['mac']
         }

         result_list.append(scan_result)
         i += 1
   return result_list


     


# SA - open port SYN-ACK


hosts = scan(get_cli_arguments())
ports = [22,8080,80,443,53, 23, 52869]
ports_info = check_tcp_port(ports, hosts)

scan_result(ports_info)


  
   










