# ZP-Projekat-2023

Implementation of *Pretty Good Privacy (PGP)* that includes generating keys with **RSA** or **DSA+ElGamal** with 1024/2048 key size, user's own Private and Public Keyring, sending and receiving messages and possibility to import keys into keyrings, all that available through a Graphical User Interface.

Project was done with [Filip Stojsavljević](https://github.com/filipStojsa) for a course in 8th Semester named Computer Security. 

Project uses Qt Designer for it's GUI, so if any of the `.ui` files are changed, they need to be generated and converted to python code using `pyuic5 -x [FILEPATH].ui -o [FILEPATH].py`
