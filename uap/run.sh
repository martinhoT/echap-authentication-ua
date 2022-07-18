echap_n=20
if [ -n "$1" ]
then
    echap_n=$1
fi

FLASK_APP=uap.py FLASK_RUN_PORT=1919 FLASK_ENV=development ECHAP_N=$echap_n flask run
