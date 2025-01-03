# hash-cr
hash cracking 







<h1> instructions</h1>






Using the built-in wordlist:
bash
Copy code
python3 run.py -h hash -t md5



Using an external wordlist:
bash
Copy code
python3 run.py -h hash -t sha256 -w wordlist.txt




With brute force enabled:
bash
Copy code
python3 run.py -h -<hash>- -t sha1 -n -v
