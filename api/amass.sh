amass enum passive -dF wildcards | grep api -dir $amass_output_dir # passive subdomain enum
amass enum active -dF wildcards | grep api -dir $amass_output_dir # active subdomain enum
amass intel -dF wildcards -whois -dir $amass_output_dir #whois lookup
amass enum -active -brute -w $wordlist_FILE -d domain -dir $amass_output_dir output_dir
amass viz -enum -d3 -dF wildcards -dir $amass_output_dir
