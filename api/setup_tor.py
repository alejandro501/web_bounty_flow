import requests
import sys

def check_tor():
    try:
        # Test if we can reach the Tor network
        response = requests.get('http://httpbin.org/ip', proxies={'http': 'socks5h://localhost:9050', 'https': 'socks5h://localhost:9050'})
        if response.status_code == 200:
            print("Tor is running and accessible.")
            return True
        else:
            print("Tor is not accessible.")
            return False
    except requests.RequestException as e:
        print(f"Error connecting to Tor: {e}")
        return False

if __name__ == '__main__':
    if not check_tor():
        sys.exit(1)
