CS463 - HIE Phase I
Joseph Leong (leong1), Brett Stevens (steven10), Danielle Saletnik (dsalet2)

Dependencies: Java, (sqlite3 - for server only)

Decompress - run:
	tar xzf hie.tgz
	(cd hie/)

Server - to start the data server, run:
	java -jar DataServer.jar

Server - to start the key server, run:
	java -jar KeyServer.jar 

Server - to start the authentication server, run:
	java -jar AuthServer.jar [DataServerIPAddress KeyServerIPAddress]

Clients - to start a client, run:
	java -jar HISPClient.jar [AuthServerIPAddress]
	java -jar PHRClient.jar [AuthServerIPAddress]
	java -jar RAClient.jar [AuthServerIPAddress]

If ip addresses are not provided, they default to 'localhost'

Requests can be issued via the command-line interface provided by each client.
It should be fairly self-explanatory.  You may select requests by either typing the single quoted
strings, such as: 'create' to create a new EHR, or by typing the corresponding number in 
parenthesis, ie. 1

Data - I will be packaging some sample sqlite3 databases: ds.db, ks.db, user.db
They were created using the java files in src/DB

The default Username/Passwords:
Doctor1/Password1
Doctor2/Password2
Patient1/Password1
Patient1/Password1
RA1/Password1
RA2/Password2
Nurse/nurse
