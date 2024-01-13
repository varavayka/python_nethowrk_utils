from  scapy.all import ARP, Ether, ls, sendp, send,srp1,srp,sr
import argparse
def scan(ip):

    
   arp_request = ARP(pdst=ip)
   broadcast  = Ether(dst="ff:ff:ff:ff:ff:ff")
   answered_list, unanswered_list = srp(broadcast / arp_request, timeout=1, verbose=False)
   delimeter = 50 * '_'
   result_list = []
   print(f'{delimeter}\n\xa0\xa0IP\t\t\t\t\tMAC\n{delimeter}')
   
   for i in answered_list:
      result_dict = dict()
      result_dict['ip'] = i[1].psrc
      result_dict['mac'] = i[1].hwsrc

      result_list.append(result_dict)

   return result_list

def scan_result(host_list):
   counts = 1
   for host in host_list:
      table_hosts = f"\n{counts}.\xa0{host['ip']}\t\t\t{host['mac']}"
      counts += 1
      print(table_hosts)

def get_cli_arguments():
   parser = argparse.ArgumentParser()
   parser.add_argument('-t', '--target', dest='target', help='Target IP / IP range')
   return parser.parse_args().target


scan_result(scan(get_cli_arguments()))
