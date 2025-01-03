# hash-cr
hash cracking 







<h1> https://wallpapers.com/images/high/4k-programming-python-logo-95ep7q9hm984yxg8.webp</h1>






Using the built-in wordlist:
bash
Copy code
python3 hash_cracky.py -h <hash> -t md5



Using an external wordlist:
bash
Copy code
python3 hash_cracky.py -h <hash> -t sha256 -w wordlist.txt




With brute force enabled:
bash
Copy code
python3 hash_cracky.py -h <hash> -t sha1 -n -v
