# psychic-spoon

This proxy is used as a proof of concept to detect SSH tunneling over HTTP.

## Detection methods

* Searching for SSH- pattern in HTTP payload
* Find if the given content type match a detected content type
* Blacklisting user agents
* Check if response content length is zero
* Looking for SSH handshake
	- SSH handshake can be detected by looking at size of packets
* Count number of HTTP get and HTTP post
* Replay HTTP get requests
* Check if total number of HTTP requests is lower than 300
* Search for echoed HTTP packets
	- Each keystrokes sends over SSH are echoed back to the client by the server.
	
A cleaner is used to reduce to score

### Note yet implemented
* Compute playload entropy

## Bibliography

* https://www.trisul.org/blog/reverse-ssh/post.html
* https://www.youtube.com/watch?v=K986WVvtNF4
* https://www.sstic.org/media/SSTIC2006/SSTIC-actes/Detection_de_tunnels_en_peripherie_du_reseau/SSTIC2006-Slides-Detection_de_tunnels_en_peripherie_du_reseau-thivillon_lehembre.pdf
* https://www.sans.org/reading-room/whitepapers/detection/detecting-preventing-unauthorized-outbound-traffic-1951
* https://forums.freebsd.org/threads/prevent-ssh-tunneling-through-port-80.40854/
* http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.591.1658&rep=rep1&type=pdf
* https://sharkfestus.wireshark.org/sharkfest.13/presentations/SEC-16_I-Can-Hear-You-Tunneling_Alex-Weber.pdf
* https://wiki.archlinux.org/index.php/HTTP_tunneling
