import hop_by_hop_checker
import sort_subdomains
import argparse

def main():
    # arguments
    parser = argparse.ArgumentParser(description="Hop-by-hop header vulnerability checker and subdomain sorter.")
    parser.add_argument('--port', type=int, help="Specify a proxy port (e.g., --port 8080)", default=None)
    parser.add_argument('--file', type=str, help="Specify the path to the subdomains file (default: live_subdomains.txt)", default='live_subdomains.txt')
    parser.add_argument('--ca', type=str, help="Path to the custom CA certificate file", default=None)
    parser.add_argument('--threads', type=int, help="Number of threads to use (default: 5)", default=5)
    args = parser.parse_args()

    proxies = None
    if args.port:
        proxies = {
            'http': f'http://localhost:{args.port}',
            'https': f'http://localhost:{args.port}',
        }
        print(f"Using proxy on port {args.port} for forwarding requests...")

    subdomains = hop_by_hop_checker.load_subdomains(args.file)

    hop_by_hop_checker.run_checks_in_threads(subdomains, proxies, verify=args.ca if args.ca else False, max_workers=args.threads)

    sort_subdomains.sort_subdomains(args.file)

if __name__ == "__main__":
    main()
