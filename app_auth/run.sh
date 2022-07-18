# Create the database in case it doesn't exist
if [ ! -e "data.db" ]
then
    python3 database.py
fi

app=app.py
if [ "$1" = "attacker" ]
then
    app=app_attacker.py
fi

FLASK_APP=$app FLASK_ENV=development FLASK_RUN_HOST=localhost FLASK_RUN_PORT=5000 flask run
