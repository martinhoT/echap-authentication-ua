# Running the UAP

In order to run the UAP, simply run the `run.sh` script:
```bash
./run.sh
```

This script allows setting the E-CHAP's number of iterations as the first argument (default is 20), and already includes various environment variables that are used by Flask and the UAP.

The UAP's database is stored in a binary file called `data`. If the database is to be cleared, then delete this file.