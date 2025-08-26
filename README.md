# THM-Brim

This will be my process of going through the Brim modules in THM.


**1. Process the "sample.pcap" file and look at the details of the first DNS log that appear on the dashboard. What is the "qclass_name"?**

First thing I do is I uploaded the sample pcap. Found the first DNS log and double clicked it for properties.

<img width="716" height="505" alt="Screenshot 2025-08-25 135332" src="https://github.com/user-attachments/assets/d2ed6655-649d-4deb-a08b-97f49901d434" />

<img width="456" height="32" alt="Screenshot 2025-08-25 135346" src="https://github.com/user-attachments/assets/150d8a14-c12d-4972-8899-474377f9c103" />

**2. Look at the details of the first NTP log that appear on the dashboard. What is the "duration" value?**

First I find the first NTP log. Then select it to see correlation.

<img width="719" height="49" alt="Screenshot 2025-08-25 135500" src="https://github.com/user-attachments/assets/0f0f110f-21aa-4e72-a624-05c685d0ee8a" />

<img width="498" height="214" alt="Screenshot 2025-08-25 135508" src="https://github.com/user-attachments/assets/9e831808-ddac-433f-ad46-ff18e05fb3ba" />

**3. Look at the details of the STATS packet log that is visible on the dashboard. What is the "reassem_tcp_size"?**

First I go to the STATS log and select it for more details.

<img width="462" height="42" alt="Screenshot 2025-08-25 135648" src="https://github.com/user-attachments/assets/6994617f-73c4-4970-91a2-30577cb15ebd" />

**4. Investigate the files. What is the name of the detected GIF file?**

First upload the Task 4 pcap. Then under Queries I select `filename` then look for GIF.

<img width="722" height="477" alt="Screenshot 2025-08-25 140927" src="https://github.com/user-attachments/assets/93765151-6145-4b06-a400-b4acbc3ed76b" />

**5. Investigate the conn logfile. What is the number of the identified city names?**

First I started with the command `_path=="conn"` to get all conn logs, then I saw that a longitude and latitude was listed. After cutting those I see 2 different adresses.

`_path=="conn" | cut geo.orig.latitude,geo.orig.longitude | sort geo.orig.latutude,geo.orig.longitude`

<img width="583" height="629" alt="Screenshot 2025-08-25 141915" src="https://github.com/user-attachments/assets/d9ddbc31-46a0-4028-8f46-6771b6a0f265" />

**6. Investigate the Suricata alerts. What is the Signature id of the alert category "Potential Corporate Privacy Violation"?**

First I selected `Suraticata Alert by Category` then I added `| cut alert.signature_id` to get the answer.

<img width="655" height="335" alt="Screenshot 2025-08-25 142612" src="https://github.com/user-attachments/assets/623e1650-1c23-4b3e-9096-eec8b7556c37" />

**7.What is the name of the file downloaded from the CobaltStrike C2 connection?**

First I used the command `_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri` to find files downloaded. 

Once I found a downlaod file, that was the answer.

<img width="724" height="369" alt="Screenshot 2025-08-25 145316" src="https://github.com/user-attachments/assets/09cda40c-1f83-4b8e-bc09-9ea03bac73b6" />

**8. What is the number of CobaltStrike connections using port 443?**

Now that I know the ip of the C2 server we can run the below command for searching in the conn files, looking only at the responding port and host, using the malicous IP, and finally only counting the uniqe fields.

`_path=="conn" | cut id.resp_p, id.resp_h | 104.168.44.45 | uniq -c`

<img width="724" height="256" alt="Screenshot 2025-08-25 151057" src="https://github.com/user-attachments/assets/34782bcd-cfdd-4938-8ef6-79220cb52b8b" />

**9. There is an additional C2 channel in used the given case. What is the name of the secondary C2 channel?**

First I clicked Suricata Alerts by Category. Then noticed 1 saying their is a Trojan detected. I right click it and move to pivot.

<img width="530" height="268" alt="Screenshot 2025-08-25 151746" src="https://github.com/user-attachments/assets/5ec8f47c-dab7-4531-941f-11caec4106b6" />

After some personal research I found IcedID and looking it up I found it is a BokBot.

**10. How many connections used port 19999?**

First command I tried was `_path=="conn" | cut id.resp_p` but this output a full list of ports, I need to sort, then count the unique entries.

The command that works is `_path=="conn" | cut id.resp_p | sort | uniq -c`

<img width="610" height="338" alt="Screenshot 2025-08-25 152943" src="https://github.com/user-attachments/assets/53484067-4764-450a-bab9-49f61fda77c2" />

**11. What is the name of the service used by port 6666?**

Command tried was `_path=="conn" | cut id.resp_p, service | sort | uniq`

<img width="719" height="407" alt="Screenshot 2025-08-25 153120" src="https://github.com/user-attachments/assets/4ea7d44c-a0f0-4d64-bbac-c584b06766cd" />

**12. What is the amount of transferred total bytes to "101.201.172.235:8888"?**

Breaking down the command used, I am looking at the conn files, only needing the responding host, responding port, the bytes sent and received, then sorting the results, then only showing unique entries, and finally since it is a large list I re sort so I can find the entry I am looking for.

`_path=="conn" | cut id.resp_h, id.resp_p, service, orig_bytes, resp_bytes| sort | uniq -c | sort -r value.id.resp_h`

**13. What is the detected MITRE tactic id?**

First I select `Suricata Alerts by Category` then I pivot the Crypto category. After doing that it list the MITRE Attack ID on the right field labeled `alert.metadata.mitre_tactic_id`

(TA0040)

<img width="727" height="417" alt="Screenshot 2025-08-25 154022" src="https://github.com/user-attachments/assets/26b69aa2-0596-48cd-9d2c-207ec6a9a2a2" />



















