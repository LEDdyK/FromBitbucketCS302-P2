#!/usr/bin/python
""" cherrypy_example.py

    COMPSYS302 - Software Design
    Author: Andrew Chen (andrew.chen@auckland.ac.nz)
    Last Edited: 19/02/2018

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

import cherrypy
import urllib2
import hashlib
import json
import threading
import time

# The address we listen for connections on
defURL = "http://cs302.pythonanywhere.com"
listen_ip = "192.168.1.75"
listen_port = 10000
#Through uni wifi
reportIP = "172.23.133.15"
reportLocation = "1"
#Through home wifi
#reportIP = "210.55.80.196"
#reportLocation = "2"

#GLOBAL variables
globalUsername = "username"
globalHashedPass = "hashedPass"
globalAutoReport = False

class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }                 

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = "Welcome!<br>"
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br>"
            Page += "Here is some bonus text because you've logged in!"
        except KeyError: #There is no username
            Page += "Click here to <a href='/login'>login</a>."
        return Page
    
    @cherrypy.expose
    def login(self):
        Page = '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    @cherrypy.expose
    def getonlineusers(self):
        #open url
        API = "/getList"
        username = "?username=" + cherrypy.session['username']
        password = "&password=" + cherrypy.session['hashedPass']
        response = urllib2.urlopen(defURL + API + username + password)
        #get url contents
        html = response.read()
        htmlLines = html.splitlines()
        #display url contents
        Page = '<br>'
        for i in htmlLines:
            Page += i
            Page += '<br>'
        return Page

    @cherrypy.expose
    def initReport(self):
        global background
        self.report()
        #setup online report thread (run after 60 seconds)
        background = threading.Timer(60, self.backgroundReport)
        background.start()
        raise cherrypy.HTTPRedirect('/getonlineusers')

    @cherrypy.expose
    def report(self):
        #open url
        API = "/report"
        username = "?username=" + globalUsername
        password = "&password=" + globalHashedPass
        ip = "&ip=" + reportIP
        port = "&port=" + str(listen_port)
        location = "&location=" + reportLocation
        pubkey = ""
        enc = ""
        response = urllib2.urlopen(defURL + API + username + password + ip + port + location + pubkey + enc)

    def backgroundReport(self):
        while globalAutoReport:
            #open url
            API = "/report"
            username = "?username=" + globalUsername
            password = "&password=" + globalHashedPass
            ip = "&ip=" + reportIP
            port = "&port=" + str(listen_port)
            location = "&location=" + reportLocation
            pubkey = ""
            enc = ""
            response = urllib2.urlopen(defURL + API + username + password + ip + port + location + pubkey + enc)
            print "report sent"
            #run this every 60 seconds
            time.sleep(60)
        
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        global globalUsername
        global globalHashedPass
        global globalAutoReport
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = self.authoriseUserLogin(username,password)
        if (error == 0):
            #define global variables
            cherrypy.session['username'] = username
            cherrypy.session['hashedPass'] = hashlib.sha256(str(password+username)).hexdigest()
            globalUsername = username
            globalHashedPass = hashlib.sha256(str(password+username)).hexdigest()
            globalAutoReport = True
            #report to login server
            self.initReport()
            raise cherrypy.HTTPRedirect('/getonlineusers')
        else:
            raise cherrypy.HTTPRedirect('/logintest')

    @cherrypy.expose
    def signout(self):
        global globalAutoReport
        """Logs the current user out, expires their session"""
        API = "/logoff"
        username = "?username=" + cherrypy.session.get('username')
        password = "&password=" + cherrypy.session.get('hashedPass')
        enc = ""
        globalAutoReport = False
        if (username == None):
            pass
        else:
            response = urllib2.urlopen(defURL + API + username + password + enc)
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

    #TODO
    #Allowing this only allows the user lkim564 to login through this script
    #Adjust so that anyone may log in
    def authoriseUserLogin(self, username, password):
        hashedPass = hashlib.sha256(str(password+username)).hexdigest()
        if (username == "lkim564") and (hashedPass == "d9174a05cbe8d7707c53d7d5b78ce6190cd65a8f0fbc849dc966d962a88302e3"):
            return 0
        else:
            return 1
          
def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/")

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True,
                           })

    print "========================="
    print "University of Auckland"
    print "COMPSYS302 - Software Design Application"
    print "========================================"                       
    
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()
