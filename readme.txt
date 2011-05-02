CS463 - HIE Phase I
Joseph Leong (leong1), Brett Stevens (steven10), Danielle Saletnik (dsalet2)

Dependencies: Java, Ant, (sqlite3 - for server only)

Decompress - run:
	tar xzf hie.tgz
	(cd hie/)

Build - to build run, from project root, in a terminal:
	ant build

Server - to start the server, run:
	ant DataServer
OR 

Clients - to start a client, run:
	ant HISPagent
	ant PHRagent

Requests cann be issued to the DS via the command-line interface provided by each client.
It should be fairly self-explanatory.  You may select requests by either typing the single quoted
strings, such as: 'create' to create a new EHR, or by typing the corresponding number in 
parenthesis, ie. 1

Data - I will be packaging some sample sqlite3 databases: DS.db, PHR.db, HISP.db
They can be replicated by running:
	ant AuthDbHISP
	ant AuthDbPHR
	ant SampleEHRDBCreation

The default Username/Passwords:
Doctor1/password1
Doctor2/password2
Nurse1/password1
Patient1/password1

Clean - to clean up compiled files you may run:
	ant clean
