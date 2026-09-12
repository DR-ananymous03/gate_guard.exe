import time
import sys
import subprocess
import re


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}   ____      _      ____                     _     
  / ___| ___| |_   / ___| _   _  __ _ _ __  __| |    
 | |  _ / _ \\ __| | |  _ | | | |/ _` | '__|/ _` |    
 | |_| |  __/ |_  | |_| || |_| | (_| | |  | (_| |    
  \\____|\\___|\\__|  \\____| \\__,_|\\__,_|_|   \\__,_|    
{Colors.ENDC}
{Colors.HEADER} [+] Secure Network Route & ARP Shield Active{Colors.ENDC}
    """
    print(banner)


class GateGuard:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.trusted_mac = None

    def get_mac(self):
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, shell=True)
            output = result.stdout

            for line in output.splitlines():
                if self.target_ip in line:
                    match = re.search(
                        r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                        line)
                    if match:
                        return match.group(1).replace("-", ":")
        except Exception as e:
            pass
        return None

    def start_monitoring(self, interval=5):
        print(f"\n{Colors.BLUE}[*] Initializing secure baseline for target...{Colors.ENDC}")

        subprocess.run(f"ping -4 -n 1 {self.target_ip}", capture_output=True, shell=True)
        self.trusted_mac = self.get_mac()

        if not self.trusted_mac:
            print(f"{Colors.FAIL}[!] Critical: Failed to establish baseline. Check connection!{Colors.ENDC}")
            sys.exit(1)

        print(f"{Colors.GREEN}[✔] Baseline locked. Starting live network feed...{Colors.ENDC}")
        print(
            f"{Colors.CYAN}[*] Press Ctrl+C to stop at any time.\n{Colors.HEADER}--------------------------------------------------{Colors.ENDC}")

        try:
            check_count = 1
            while True:
                subprocess.run(f"ping -4 -n 1 {self.target_ip}", capture_output=True, shell=True)
                current_mac = self.get_mac()
                timestamp = time.strftime("%H:%M:%S")

                if current_mac and current_mac != self.trusted_mac:
                    print(
                        f"\n{Colors.FAIL}{Colors.BOLD}[!] ALERT [{timestamp}]: GATEWAY MAC SPOOFING DETECTED! [!]{Colors.ENDC}")
                    print(f"{Colors.FAIL}    [Expected Signature]: {self.trusted_mac}")
                    print(f"{Colors.Malicious}    [Malicious Signature]: {current_mac}{Colors.ENDC}")
                    print(f"{Colors.WARNING}    -> Warning: Traffic interception attempt active!{Colors.ENDC}\n")
                elif not current_mac:
                    print(
                        f"{Colors.WARNING}[-] Warning [{timestamp}]: Target responding slowly or unreachable...{Colors.ENDC}")
                else:
                    print(
                        f"{Colors.GREEN}[INFO] [{timestamp}] Check #{check_count} | Route Status: SECURE | Active MAC: {current_mac}{Colors.ENDC}")
                    check_count += 1

                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[*] GateGuard stopped. Stay safe!{Colors.ENDC}")


if __name__ == "__main__":
    print_banner()

    user_gateway = input(f"{Colors.CYAN}[?] Enter Gateway IP to initialize shield: {Colors.ENDC}").strip()

    if not user_gateway:
        sys.exit(1)

    guard = GateGuard(target_ip=user_gateway)
    guard.start_monitoring(interval=5)