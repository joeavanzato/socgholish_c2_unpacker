## **Only use this in a contained environment to ensure no accidental C2 connection is established.**

Basic decryption routine for the encrypted Python reverse shell payload typically dropped as a Scheduled Task as discussed at https://www.trendmicro.com/en_us/research/25/c/socgholishs-intrusion-techniques-facilitate-distribution-of-rans.html

Just run the script with the payload as the first argument like 'python socgholish_c2_decrypter.py payload.jar'

By default, the script will output the final decrypted payload to 'decrypted_source.txt' in your cwd.

Since this type of thing changes very rapidly, there will probably be a likelihood to adjust the regex to your individual payload.

If someone finds this is not working, feel free to DM me on Discord or similar and I can help you with your specific payload.

The code is pretty ugly, I might decide to come back and clean it up/fully document but this worked for my needs for now.