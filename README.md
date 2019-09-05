# encryption_project
The project is a web app where users can register and share their secrets anonymously (like the app whisper).
The various commits show the increasing levels of security for user authentication:

Commit 1 - Password encryption with long string stored in the enviromental variables .env file
Commit 2 - Hashing using md5 protocol
Commit 3 - Hashing and salting using the bcrypt npm module
Commit 4 - Using the passport npm module to implement session cookies for user auth with local strategy
Commit 5 - Using passport with Google and Facebook user auth strategies
Commit 6 - Implementation of the app functionality (posting a secret) by authenticated users. 
