Introduction:

This is a writeup for the "Disk Analysis & Autopsy" TryHackMe room: 
https://tryhackme.com/room/autopsy2ze0

This writeup will assume basic knowledge of Windows, directory structures, and
Autopsy based on the previous Autopsy room.  
--------------------------------------------------------------------------------
Overview:

NAME: "Disk Analysis & Autopsy"
DESCRIPTION: 
"Ready for a challenge? Use Autopsy to investigate artifacts from a disk image."

--------------------------------------------------------------------------------
Task 1:
--------------------------------------------------------------------------------
Question 1: What is the MD5 hash of the E01 image?

Open up Autopsy, select HASAN2.EO1 in the data sources tree. Under the Metadata
tab, the MD5 hash is displayed.

--------------------------------------------------------------------------------
Question 2: What is the computer account name?

Under the same tab as before, the name is displayed.

--------------------------------------------------------------------------------
Question 3: List all the user accounts. (alphabetical order)

This can be done a number of ways. The easiest is under the Results tab,
Extracted Content -> Operating System User Account.

Ignoring the obviously system-generated names, list them out in order.
(Side note: This analyst believes that these usernames are all of South Asian,
likely Indian origin)

--------------------------------------------------------------------------------
Question 4: Who was the last user to log into the computer?

It is possible to guess this based off the length of the username alone, but the
proper way is to sort the users found in question 3 by access date, and then
taking the top one.

--------------------------------------------------------------------------------
Question 5: What was the IP address of the computer?

Exploring around the directories reveals the network monitoring tool Look@LAN in
the Program Files (x86) directory. Looking at the irunin.ini file, one can find
the IP address listed under %LANIP%=[redacted].

--------------------------------------------------------------------------------
Question 6: What was the MAC address of the computer?

The MAC address of the computer is listed in the same file as the IP address,
under %LANNIC%=[redacted]. This could have also been found by searching for the
term "NIC".

--------------------------------------------------------------------------------
Question 7: Name the network cards on this computer.

Looking up the location where the network card name is stored actually yields a
number of OTHER autopsy tutorials if one includes "autopsy" in the search. These
tutorials were useful in that they explained that the file is stored in the path
C:\WINDOWS\system32\config\software\Microsoft\Windows NT\CurrentVersion\NetworkCards\

Autopsy and Windows seem to represent the SOFTWARE directory as a registry hive.
Fortunately, the path can be pursued by selecting "SOFTWARE" as the file and
using the "Application" tab that pops up below the listing window to traverse
the path to the end. Clicking our way down, we see two registers:

"ServiceName" and "Description". Description is human-readable and also matches
the format requested by the question.
--------------------------------------------------------------------------------
Question 8: What is the name of the network monitoring tool?

This was found during the previous stages of the investigation, and can simply
be stated from knowledge. The name alone should be more than enough to tip you
off as to its purpose. (See the tool mentioned in Questions 5 and 6)

--------------------------------------------------------------------------------
Question 9: A user bookmarked a Google Maps location. What are the coordinates 
of the location?

Under Results -> Extracted Content -> Web Bookmarks, the bookmarks of all users
are listed. Only one bookkmark's URL has a google maps URL. The correct format
for the question can be copied from the file's data (with the degree symbol).

The location appears to be the location of GeoFiny Technologies Pvt ltd, Ward
200, Chennai - 600119, Tamil Nadu, India. This supports the investigator's
earlier inference that the users were from India.

--------------------------------------------------------------------------------
Question 10: A user has his full name printed on his desktop wallpaper. What is 
the user's full name?

A user's current wallpaper is cached in the following directory.
C:\Users\%USER%\Appdata\Roaming\Microsoft\Themes\CachedFiles

Searching through the various users' caches, one user's directory contains a
custom desktop image, with his name in the top left corner.
--------------------------------------------------------------------------------
Question 11:
A user had a file on her desktop. It had a flag but she changed the flag using 
PowerShell. What was the first flag?

The pronouns possibly give us a hint as to which users' names to check first.
While not a terribly useful hint, this investigator has met quite a few Indian
women named Shreya, and decided that would be a good place to start. Shreya's
desktop yields the file mentioned in the prompt.

Simply searching for "flag{" in the keyword search on Autopsy would yield the
same results, but in the interest of thoroughness, the following path has the
history of the PowerShell console mentioned:

C:\Users\%USER%\Appdata\Roaming\Microsoft\Windows\Powershell\PSReadline\

The specific file is "ConsoleHost_history.txt" in that directory. Reading the
file contents, one sees the Add-Content command used to edit the file, and thus
the flag can be obtained.

--------------------------------------------------------------------------------
Question 12: The same user found an exploit to escalate privileges on the 
computer. What was the message to the device owner?

Seeing the file "exploit.ini" in shreya's Desktop directory, looking at the
indexed text of the file. Reading the text in the file, the flag can be found.

--------------------------------------------------------------------------------
Question 13: 2 hack tools focused on passwords were found in the system. What 
are the names of these tools? (alphabetical order)

A perusal of the Program Files directories didn't yield anything of note. Tools,
however, are downloaded, so it may be useful to check the downloads. This can be
done either by checking each user's individual Downloads directories, but an
easier way would be to check Results->Extracted Content->Web Downloads. This of
course relies on the user's ability to recognize the names of various tools. One
of them can be found there. Another one can be found by looking through the
Results->Extracted Content->Run Programs path. Sorting by name to cluster the
various Windows basic processes, the other password cracking tool can also be
found. This is made much easier by using the alphabetical ordering and name
length clues from the hint.

On a side note, the downloads seem to suggest that sivapriya enjoys pottery. Not
at all relevant to any of the questions, but still cool to explore.

--------------------------------------------------------------------------------
Question 14: There is a YARA file on the computer. Inspect the file. What is the
name of the author?

The most natural first reaction is to do a keyword search for ".yar", which
yields, among other things, a single file whose name actually contains the .yar
extension (although it is in fact a .lnk file). Reading through the metadata,
the name and location of the file can be found. While simply googling the name
of the directory it can be found in will quickly yield the author's name, one
can also look in the mentioned user's directories to find what can be found with
a Google search. There is a readme there which contains the author's name.

--------------------------------------------------------------------------------
Question 15: One of the users wanted to exploit a domain controller with an 
MS-NRPC based exploit. What is the filename of the archive that you found? 
(include the spaces in your answer) 

Those who have encountered Eternal Blue and Zerologon will likely immediately
search for the keyword 'Zerologon'. This gives, among other things, a .lnk file
referring to the archive in question. Quickly guessing around common archive
extensions is sufficient to get the name right.

Addendum:
The answer can apparently also be found by checking through the downloads, 
recently used files, and recently run programs. 
(Credit to user morjan 451#6573 on the TryHackMe discord!)

--------------------------------------------------------------------------------
Remarks: 

The investigator would like to thank the various members of the TryHackMe 
discord server, the room's creator heavenraiza, and the TryHackMe staff.

Probably my favorite room of the Cyber Defender path. The room also has
an incredibly "alive" and realistic feel to it, a result of the various little
details here and there that add a bit of a personal touch to the target. The use
of little images like sivapriya's pictures of pottery at a bazaar, the names and
geographic data all pointing to a coherent location, and other little personal
touches of each user gives the student the impression that the people they are
investigating are real and have real lives that they, through Autopsy and the
disk image, are able to peer into. Thanks again to heavenraiza for a wonderful
experience.

This is my first writeup and I hope you found it helpful. It feels very surreal
to be submitting it to a community whose intellects dwarf my own in every way.
While others may see this as a small achievement, it would mean a lot to me to
get some feedback! 

- Erica (@ericadoodles on the TryHackMe Discord!)
