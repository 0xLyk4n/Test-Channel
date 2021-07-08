# test-suricata


#drop http any any -> 192.168.6.1 any (; sid:10001;)
#drop http 192.168.6.1 any -> any any (Content:"Y2F0IC9ldGMvcGFzc3dkCg=="; sid:10001;)

#drop http any any -> 192.168.6.4 any (Content:"Y2F0IC9ldGMvcGFzc3dkCg=="; sid:10001;)
#drop http 192.168.6.4 any -> any any (Content:"Y2F0IC9ldGMvcGFzc3dkCg=="; sid:10001;)

#drop http any any -> 192.168.10.2 any (Content:"Y2F0IC9ldGMvcGFzc3dkCg=="; sid:10001;)
#drop http 192.168.10.2 any -> any any (Content:"Y2F0IC9ldGMvcGFzc3dkCg=="; sid:10001;)


drop http any any -> any any (msg:"cat etc/passwd"; http.uri; content:"id="; \
     base64_decode:bytes 24, offset 0, relative; \
     base64_data; content:"cat /etc/passwd"; sid:10001; rev:1;)

drop http any any -> any any (msg:"mysql"; http.uri; content:"id="; \
     base64_decode:bytes 18, offset 0, relative; \
    base64_data; content:"mysql --user="; sid:10002; rev:1;)

drop http any any -> any any (Content:"curl/7.58.0" http_user_agent; sid:10003;)
drop http any any -> any any (Content:"93.119.154.165" xff; sid:10004;)




#drop tcp any any -> 192.168.6.1 any ()
#drop tcp 192.168.6.1 any -> any any ()

#drop tcp any any -> 192.168.6.4 any ()
#drop tcp 192.168.6.4 any -> any any ()

#drop tcp any any -> 192.168.10.2 any ()
#drop tcp 192.168.10.2 any -> any any ()

#drop tcp 192.168.10.2 any -> 192.168.10.254 any (msg: "TCP packet to malicious host, Drop"; sid:10001;)
#drop tcp 192.168.10.254 any -> 192.168.10.2 any (msg: "TCP packet from malicious host, Drop"; sid:10002;)

#drop udp 192.168.10.2 any -> 192.168.10.254 any (msg: "UDP packet to malicious host, Drop"; sid:10003;)
#drop udp 192.168.10.254 any -> 192.168.10.2 any (msg: "UDP packet from malicious host, Drop"; sid:10004;)

#drop tcp any any -> 192.168.10.2 any (msg: "TCP packet to malicious host, Drop"; sid:10005;)
#drop tcp 192.168.10.2 any -> any any (msg: "TCP packet from malicious host, Drop"; sid:10006;)

#drop udp any any -> 192.168.10.2 any (msg: "UDP packet to malicious host, Drop"; sid:10007;)
#drop udp 192.168.10.2 any -> any any (msg: "UDP packet from malicious host, Drop"; sid:10008;)

#drop tcp any any -> 192.168.6.4 any (msg: "TCP packet to malicious host, Drop"; sid:10009;)
#drop tcp 192.168.6.4 any -> any any (msg: "TCP packet from malicious host, Drop"; sid:10010;)

#drop udp any any -> 192.168.6.4 any (msg: "UDP packet to malicious host, Drop"; sid:10011;)
#drop udp 192.168.6.4 any -> any any (msg: "UDP packet from malicious host, Drop"; sid:10012;)
