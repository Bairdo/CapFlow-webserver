#!/usr/bin/env python
#-*- coding:utf-8 -*-

# WARNING: this web application is just a toy and should not be used for
# production purposes.

# TODO: make a more serious and configurable web application. It could even be
# based on this one.

from cgi import parse_qs, escape
import json
import urlparse
from wsgiref.util import shift_path_info
import os
import os.path
import urllib
import urllib2

import sys
sys.path.append("../")

from config import CTL_REST_IP, CTL_REST_PORT

PLAIN = 0
HTML = 1
JSON = 2
CSS = 3
JS = 4
GIF = 5
PNG = 6
JPEG = 7

CONTENT_TYPES = {
PLAIN: "text/plain",
HTML: "text/html",
JSON: "application/json",
CSS: "text/css",
JS: "text/javascript",
GIF: "image/gif",
PNG: "image/png",
JPEG: "image/jpeg",
}

exts = {
".js": JS,
".html": HTML,
".css": CSS,
".png": PNG,
".gif": GIF,
".jpg": JPEG,
".jpeg": JPEG,
".json": JSON,
}

USERS = {
    "eder": "abc",
    "allan": "def",
    "test": "test",
"host102user": "host102pass",
"host103user": "host103pass",
"host104user": "host104pass",
"host105user": "host105pass",
"host106user": "host106pass",
"host107user": "host107pass",
"host108user": "host108pass",
"host109user": "host109pass",
"host110user": "host110pass",
"host111user": "host111pass",
"host112user": "host112pass",
"host113user": "host113pass",
"host114user": "host114pass",
"host115user": "host115pass",
"host116user": "host116pass",
"host117user": "host117pass",
"host118user": "host118pass",
"host119user": "host119pass",
"host120user": "host120pass",
"host121user": "host121pass",
"host122user": "host122pass",
"host123user": "host123pass",
"host124user": "host124pass",
"host125user": "host125pass",
"host126user": "host126pass",
"host127user": "host127pass",
"host128user": "host128pass",
"host129user": "host129pass",
"host130user": "host130pass",
"host131user": "host131pass",
"host132user": "host132pass",
"host133user": "host133pass",
"host134user": "host134pass",
"host135user": "host135pass",
"host136user": "host136pass",
"host137user": "host137pass",
"host138user": "host138pass",
"host139user": "host139pass",
"host140user": "host140pass",
"host141user": "host141pass",
"host142user": "host142pass",
"host143user": "host143pass",
"host144user": "host144pass",
"host145user": "host145pass",
"host146user": "host146pass",
"host147user": "host147pass",
"host148user": "host148pass",
"host149user": "host149pass",
"host150user": "host150pass"

}


def reply(start_response, status_code, ctype=None, content=None):
    if ctype is not None:
        start_response(status_code, [("Content-Type", CONTENT_TYPES[ctype]),
                                     ("Content-Length", str(len(content)))])
    else:
        start_response(status_code, [])

    if content is None:
        return []
    return content


def redirect(start_response, destination):
    start_response('303 See Other',  [("Location", destination)])
    return []


def get_client_address(environ):
    try:
        return environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
    except KeyError:
        return environ['REMOTE_ADDR']


def send_auth_request(ip, user):
    server = "{:s}:{:s}".format(CTL_REST_IP, CTL_REST_PORT)
    #todo send user
    print server
    url = "http://{:s}/v1.0/authenticate/ip={:s}&user={:s}".format(server, ip, user)

    print url
    params = urllib.urlencode({})
    response = urllib2.urlopen(url, params).read()
    print response


def send_deauth(ip):
    server = "{:s}:{:s}".format(CTL_REST_IP, CTL_REST_PORT)
    user = "NULL"
    url = "http://{:s}/v1.0/authenticate/ip={:s}&user={:s}".format(server, ip, user)

    opener = urllib2.build_opener(urllib2.HTTPHandler)
    request = urllib2.Request(url)
    request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    request.get_method = lambda: 'DELETE'
    url = opener.open(request)



def application(env, start_response):
    #print env
    old_path = env["PATH_INFO"]
    path = shift_path_info(env)
    request = parse_qs(env["QUERY_STRING"])
    try:
        callback = request["callback"][0]
    except KeyError:
        callback = None

    status = 404
    rbody = ""
    ctype = PLAIN

    print "path:'%s'" % path
    if path == "auth":
        if "CONTENT_LENGTH" in env:
            try:
                len_ = int(env["CONTENT_LENGTH"])
                body = env['wsgi.input'].read(len_)
            except ValueError:
                return reply(start_response, "400 Bad Request", PLAIN,
                             "Missing login information.")

            request = parse_qs(body)
            try:
                username = request["username"][0]
                password = request["password"][0]
                redirect_target = request["redirect"][0]
            except KeyError, IndexError:
                return reply(start_response, "400 Bad Request",
                             "Missing login information.")
            if username not in USERS or USERS[username] != password:
                return reply(start_response, "401 Unauthorized", PLAIN,
                             "Unauthorized access.")
            text = (
                "Authenticated. "
                "Redirecting to <a href='%(url)s'>%(url)s</a> in 10 seconds. "
                "<meta http-equiv='refresh' content='10;%(url)s'>"
                ) % {'url': escape(redirect_target)}
            print "about to add flows to controller"
            send_auth_request(get_client_address(env), username)
            print "added flows to controller (or failed). the method returned"
            return reply(start_response, "200 OK", HTML, text)
    elif path == "login":
        request = parse_qs(env["QUERY_STRING"])
        content = open("login.html", "r").read()
        content = content % {"redirect": request['redirect'][0]}
        return reply(start_response, "200 OK", HTML, content)
    elif path == "logout" or path == "logoff":
        content = open("logout.html", "r").read()
        return reply(start_response, "200 OK", HTML, content)
    elif path == "loggedout":
        content = open("goodbye.html", "r").read()
        # send logout message to controller here
	ip = get_client_address(env)
	print "logging of user on IP: " + ip
	send_deauth(ip)
	return reply(start_response, "200 OK", HTML, content)
    else:
        # Return file
        path = os.path.join(os.getcwd(), path + env["PATH_INFO"])
        if os.path.exists(path) and os.path.isfile(path):
            f = open(path, "r")
            rbody = f.read()
            ctype = exts[os.path.splitext(path)[1]]
            f.close()
            return reply(start_response, "200 OK", ctype, rbody)
        # Couldn't find path, redirect to login
        else:
            target = urllib.urlencode({
                "redirect": "http://" + env["HTTP_HOST"] + "/" + old_path +
                env["PATH_INFO"] + "?" + env["QUERY_STRING"]
            })
            print target
            return redirect(start_response, "/login?%s" % target)
