# what to do
## [`password bruteforce`]
```sh
wfuzz -d {} --H 'Content-Type: applications/json' -z file,/wordlist.txt https://url/auth
```
