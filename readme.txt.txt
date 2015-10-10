Communication between clients is secured using an open source implementation of TLS called OpenSSL.

A 4-way handshake performs authentication when a client connects to the chatroom. It involves exchange of certificates and selection of cipher suite for secure communication. The server sends a session key to the client encrypted with the client's public key. Each client shares a separate session key with the server. Clients use symmetric key cryptography and shared session keys to exhange messages. 




Interface:



Clients use a command line interface for communication. After a client has connected to the server and has been authenticated, the server asks it to choose a user-name for itself. Henceforth, the client can request for any of the following three services from the server:



1. Send message to another client
:	

Client is asked to provide the server issued client-id of the receiver. The client-id can be determined by referring to the list of active clients which is also a service provided by the server. He/she is then required to type the message and press enter.	



2. Show new messages received:	



Any pending messages from other clients that are yet to be received are displayed.



3. Show the list of active clients:	



The list of clients that are online at that particular time is displayed. It also displays the server issued client-id associated with each username. It can be used to select the client to whom a message has to be sent. 