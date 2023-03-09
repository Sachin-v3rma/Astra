Astra finds urls, endpoints, aws buckets, api keys, tokens, etc from a given url/s. It combines the paths and endpoints with the given domain and
gives full URL. We can use it on js, html, etc files.
Astra uses asynchronous method to fetch URLs using python's aiohttp and asyncio.
Its a combination of linkfinder and secretfinder. Uses Regex's from linkfinder, secretfinder and nuclei templates. 
Although None of them worked exactly because python's regex r way different.
So basically everyone of them is modified by me.

# Installation
	git clone https://github.com/Sachin-v3rma/Astra && cd Astra
	pip3 install -r requirements.txt

# Usage

Takes Input from stdin, so easy to use in automation.

Flags : 
	
	-ns --> No Secretfinder. Only find urls and endpoints. Also increases the speed.
	-t  --> Threads. Only increase if you have strong internet connection.

Example :	

	cat live_subdomains.txt | python3 Astra.py
	echo https://www.example.com | python3 Astra.py -ns |tee astra_urls.txt
	cat js_urls.txt | python3 Astra.py -t 20 | anew urls_secrets.txt

Output :

	If u wanna remove the counter comment out the line 174-177 or you can use head command to remove them. 
	Use grep "\[IP\]" to grep IPs.
	Use grep "\[$\]" to grep secrets.
	Use grep "\[C\]" to grep aws buckets.
	Use grep "^http" to grep URLs.


Also decrease the threads if your internet connection is weak (like i use mobile data :( ).

# Creator

Made by Sachin Verma with <3 </br>
Twitter : sachin_vm

NO BANNER BECAUSE WHY ??

<a href="https://www.buymeacoffee.com/sachinvm" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-blue.png" alt="Buy Me A Coffee" height="41" width="174"></a>

