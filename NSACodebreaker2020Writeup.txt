NSA Codebreaker Challenge 2020
Writeup by Erica Hu (Tasks 1 through 4 complete)
Date: 29DEC2020
Notes: As the problems contain different names and numbers for different people,
	I have included the specific values for text. I wrote a script for Task
	4, but it should be trivial for anyone with basic programming skills to
	produce code to do the analysis themselves.
Writeup:
--------------------------------------------------------------------------------
Part 1:
Problem Text:

In accordance with USSID18, a collection on an American citizen is permitted in
cases where the person is reasonably believed to be held captive by a group
engaged in international terrorism. As a result, we have obtained a copy of the 
home directory from the journalist's laptop and are hoping it will contain
information that will help us to locate and rescue the hostage. Your first task 
is to analyze the data and files available in the journalist's home directory.

Problem Materials
home.zip (Downloadable Zip)

Objectives:
Find the journalist's login name 
Find the name of the encrypted keyfile.

Procedure:
Download home.zip and use the unzip command to decompress the file.
Enter the directory and find that the name of the directory in the home folder
is JaimeWigglebottom218, which is presumably the journalist's username. After
listing the files in that directory, the keyfile is called keyfile.

Answers:
JaimeWigglebottom218
keyfile
--------------------------------------------------------------------------------
Part 2:
Problem Text:
The name of the encrypted file you found implies that it might contain
credentials for the journalist's various applications and accounts. Your next
task is to find information on the journalist's computer that will allow you to
decrypt this file.

Problem Materials:
home.zip

Objectives:
Enter the password that decrypts the encrypted file

PROCEDURE:
Analysis of pwHints.txt indicates that the password for keyfile is composed of
"pet name + pet bday", bday presumably meaning birthday. With that, we now know
what information to look for. A tree listing of the home/ contents shows that 
home/Pictures/Pets contains three images, namelly couchChillin.jpg, loaf.jpg,
and shenanigans.jpg. Queued these files for metadata analysis (TODO).

The full path-listing is the following (comments added with arrows ("<--"))

\---JaimeWigglebottom218
    |   .bashrc <-- standard home directory bashrc and bash_profile files.
    |   .bash_profile
    |   keyfile <-- the file to decrypt
    |   pwHints.txt <-- the aforementioned pwHints.txt
    |   
    +---Documents
    |   \---Blog-Articles
    |           blogEntry1.txt <-- these documents may contain intel
    |           blogEntry2.txt
    |           blogIntro.txt
    |           
    +---Downloads
    \---Pictures
        +---Pets <-- Should draw immediate attention due to relevance to pets.
        |       couchChillin.jpg <-- Should analyze these files' metadata.
        |       loaf.jpg
        |       shenanigans.jpg
        |       
        \---Travels <-- these seem unlikely to be valuable sources of intel.
            +---Malta
            |       BlueGrotto.jpg
            |       MostaDome.jpg
            |       TritonFountain.jpg
            |       
            \---Wales
                    heatherFields.jpg
                    horseFeeding.jpg

An analysis of the files shows that shenanigans.jpg seems to indicate a birthday
celebration for a cat. Inserting that into JPEGsnoop shows that the value of
DateTimeOriginal and DateTimeDigitized are both "2019:12:23 11:13:23". It is
thus reasonable to conclude that the file was created on December 23, 2019, the
pet's birthday. 

With this information, we need to find the name of that cat. This cat appears to
be the same cat found in loaf.jpg and couchChillin.jpg in the same directory, as
the patterns on its fur are unique among the pets depicted in shenanigans.jpg.

An analysis of the Blog-Articles directory with a focus on mentions of a cat is
rewarded by a revelation at the end of blogIntro.txt, where Jaime Wigglebottom
reveals the name of the cat: Midori.

Combining this information, we have a guess at the password: Midori1223

ANSWERS:
Midori1223
--------------------------------------------------------------------------------
Part 3:
Problem Text:
Good news -- the decrypted key file includes the journalist's password for the
Stepinator app. A Stepinator is a wearable fitness device that tracks the number
of steps a user walks. Tell us the associated username and password for that
account. We might be able to use data from that account to track the
journalist's location!

Downloads:
home.zip

Objectives:
Enter the username for the Stepinator account
Enter the password for the Stepinator account

PROCEDURE:
First, we should determine the encryption algorithm and type. Analysis indicates
that the file is GPG symmetrically encrypted data (AES256 cipher). Using the 
command gpg --decrypt keyfile > keyfiledecrypted and entering the passphrase
obtained in Part 2 ("Midori1223"), we decrypt the file.

Proceeding to analyze this file, we can discover that it appears to be SQLite
information, with passwords and usernames displayed in text. Sanitize this data
for analysis, as there is a lot of trash. It is not strictly necessary to clean
up the file, but it does make solving the problem both easier and less painful.

To determine which username/password combination is the one we need, we refer to
pwHints.txt, which contains the following line:
stepinator: color + petName + anniversary +fdate

From analysis of the SQLite database using the sqlite command (which I installed
upon realizing what this file was), we can do the following:

.open decryptedkeyfile
This opens the database

.tables
This shows the two tables in the database to be "passwords" and "services"

.dump services
.dump passwords
It may be useful to just dump both and match the service and password.
The username/password and service can be matched to reveal the answers:
service 8 is stepinator, thus looking up the 8th service will yield the login.

The file tells us that the username is Midori_Wigglebottom_1223

Unfortunately, the password seems to be encrypted or hashed or obfuscated in 
some unknown manner. Fortunately, we do at least get some information as the
other logins may provide us with information we need.

After some looking around, it was found that this delimiter was used by Adobe to
indicate Base85 encodings of text. Using a base85 decoder of choice, the
password for stepinator account appears to be CrimsonMidori07061006.

ANSWERS:
Midori_Wigglebottom_1223
CrimsonMidori07061006

--------------------------------------------------------------------------------
Part 4:

Problem Text:
By using the credentials in the decrypted file, we were able to download the
journalist's accelerometer data from their Stepinator device from the time of
the kidnapping. Local officials have provided us with a city map and traffic
light schedule. Using these along with the journalist's accelerometer data, find
the closest intersection to where the kidnappers took the hostage

Problem Materials: 
Relevant information for solving the problem (README.txt)
Acceleration data (stepinator.json)
City map and traffic light schedule (maps.zip)

Objectives:
Enter the avenue of the intersection (ie. Avenue F & 3rd st, enter F)
Enter the street of the intersection (ie. Avenue F & 3rd st, enter 3)

PROCEDURE:
Analyzing the data yields some crucial information:
 - The kidnapping occured at F13, time t=0, and were initially headed Eastbound
 - The city lights follow patterns denoted in maps.zip
 - The acceleration data is contained in stepinator.json.

Using the laws of physics, math, and the information given in the rules, we can
track the car with decent accuracy using trapezoidal Reimann Sums:

The car can be seen to have traveled ~1100 meters, or 11 block lengths.

Time t = 0: The car travels from F13 -> G13 in 11 seconds
Time t = 11: The Car travels at full speed for 9 seconds, G13 -> H13
Time t = 19: The car crosses intersection H13, slowing to a stop at I13
Time t = 30: The lights change and the car speeds up again, heading east to J13
Time t = 42: The car continues through J13 at full speed
Time t = 51: The car comes to a stop at K13, marking its distance at 500 meters.
Time t = 61: The car begins traveling again, although the direction is unknown
Time t = 75: The car stops after travelling 100m indicating that it travelled
	longitudinally and stopped at either K14 or K12
Time t = 91: The car speeds up again, proceeding to full speed.
Time t = 102: The car crosses an intersection at full speed, either K11 or K15
Time t = 110: the car crosses an intersection, having slowed down slightly 
	beforehand, indicating a turn. It speeds back up afterwards. As the car
	is at either K11 or K15, it is either at K10 or K16 now, turning towards
	either J10, L10, J16, or L16.
Time t = 119: The car reaches an intersection and turns without stopping, thus 
	it turned right (this is, after all, American). This indicates that it
	cannot be at J10, and thus we focus on J16, L16, and L10,
Time t = 128: The car travels vertically through an intersection at full speed,
	meaning that it could not have been at Avenue L, as the lights there are
	red at this time.
Time t = 138: The car comes to a stop at the next intersection, ending the data
	provided and indicating the destination. We know that the car was moving
	north after the last turn, leading us to travel 2 blocks north from J16
	to intersection J18.

Answers:
J
18

REMARKS:

--------------------------------------------------------------------------------
