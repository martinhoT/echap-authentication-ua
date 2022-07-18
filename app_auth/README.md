# Running the Service

In order to run the Service, simply run the `run.sh` script:
```bash
./run.sh
```

This script already includes various environment variables that are used by Flask and the application.

The Service's database is stored in a Sqlite3 database file called `data.db`. If the database is to be cleared, then delete this file.

## Running the Attacker version

In order to run the Attacker version of the Service, simply run the `run.sh` script with the 'attacker' argument:
```bash
./run.sh attacker
```