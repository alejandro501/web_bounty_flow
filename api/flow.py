import sys
import x_forwarded

def main():

    use_tor = '--tor' in sys.argv or '-T' in sys.argv
    
    x_forwarded.main(
        input_file='domains.txt',
        output_file='x_forwarded_for.txt',
        log_file='log.txt',
        use_tor=use_tor 
    )

if __name__ == '__main__':
    main()
