This is forked from https://github.com/ederlf/CapFlow 

but as we use the webserver on a different machine, i've stripped out the openflow stuff, to leave just the webserver


to run

$ git clone
$ cd CapFlow-webserver/ws
# gunicorn rfweb:application -b 0.0.0.0:80


there might be some IP address that need changing in config.py
