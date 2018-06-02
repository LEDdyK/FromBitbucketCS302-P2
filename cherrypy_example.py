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
#Test purposes
globalTestMessage = "message unavailable"

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
    
###############################################################################
# SEPERATOR                                                         SEPERATOR #
#                                  SEPERATOR                                  #
# SEPERATOR                                                         SEPERATOR #
###############################################################################
 
    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = "Welcome!<br>"
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br>"
            Page += "Here is some bonus text because you've logged in!<br>"
            #Test purposes
            Page += "Test Message: "
            Page += globalTestMessage
        except KeyError: #There is no username
            Page += "Click here to <a href='/login'>login</a>."
        return Page

############################################################################### Login
    
    @cherrypy.expose
    def login(self):
        Page = '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
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
    
    #TODO
    """Allowing this only allows the user lkim564 to login through this script
    Adjust so that anyone may log in"""
    def authoriseUserLogin(self, username, password):
        hashedPass = hashlib.sha256(str(password+username)).hexdigest()
        if (username == "lkim564") and (hashedPass == "d9174a05cbe8d7707c53d7d5b78ce6190cd65a8f0fbc849dc966d962a88302e3"):
            return 0
        else:
            return 1

############################################################################### Logout
    
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

############################################################################### List Users

    @cherrypy.expose
    def getallusers(self):
        #open url
        API = "/listUsers"
        response = urllib2.urlopen(defURL + API)
        #get url contents
        html = response.read()
        htmlUsers = html.split(',')
        #display url contents
        Page = '<br>'
        for i in htmlUsers:
            Page += i
            Page += '<br>'
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

############################################################################### Report
    
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

############################################################################### Receive Messages

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self):
        global globalTestMessage
        input_dict = cherrypy.request.json
        sender = input_dict['sender']
        destination = input_dict['destination']
        message = input_dict['message']
        stamp = input_dict['stamp']
        try:
            encoding = input_dict['encoding']
        except KeyError:
            encoding = 0
        try:
            encryption = input_dict['encryption']
        except KeyError:
            encryption = 0
        try:
            hashing = input_dict['hashing']
        except KeyError:
            hashing = 0
        try:
            hexhash = input_dict['hash']
        except KeyError:
            hexhash = "nohash"
        try:
            decryptionKey = input_dict['decryptionKey']
        except KeyError:
            decryptionKey = "nokey"
        try:
            groupID = input_dict['groupID']
        except KeyError:
            groupID = "noID"
        #Test purposes
        globalTestMessage = sender + " " + destination + " " + message + " " + stamp + " " + str(encoding) + " " + str(encryption) + " " + str(hashing) + " " + hexhash + " " + decryptionKey + " " + groupID

############################################################################### Receive Files

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self):
        global globalTestMessage
        input_dict = cherrypy.request.json
        sender = input_dict['sender']
        destination = input_dict['destination']
        base64 = input_dict['file']
        filename = input_dict['filename']
        content_type = input_dict['content_type']
        stamp = input_dict['stamp']
        try:
            encryption = input_dict['encryption']
        except KeyError:
            encryption = 0
        try:
            hashing = input_dict['hashing']
        except KeyError:
            hashing = 0
        try:
            hexhash = input_dict['hash']
        except KeyError:
            hexhash = "nohash"
        try:
            decryptionKey = input_dict['decryptionKey']
        except KeyError:
            decryptionKey = "nokey"
        try:
            groupID = input_dict['groupID']
        except KeyError:
            groupID = "noID"
        #Test purposes
        globalTestMessage = sender + " " + destination + " " + base64 + " " + filename + " " + content_type + " " + stamp + " " + str(encryption) + " " + str(hashing) + " " + hexhash + " " + decryptionKey + " " + groupID

############################################################################### Send Messages

    @cherrypy.expose   
    def sendMessage(self):
        output_dict = {
            "sender":"Lite Kim",
            "destination":"Somewhere",
            "message":"Hi",
            "stamp":"00:00:00:00"
            }
        data = json.dumps(output_dict)
        req = urllib2.Request("http://192.168.1.73:10001/receiveMessage", data, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)

############################################################################### Send Files

    @cherrypy.expose   
    def sendMessage(self):
        output_dict = {
            "sender":"Lite Kim",
            "destination":"Somewhere",
            "base64":"Hi",
            "filename":"filename",
            "content_type":"content_type"
            "stamp":"00:00:00:00"
            }
        data = json.dumps(output_dict)
        req = urllib2.Request("http://192.168.1.73:10001/receiveFile", data, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)

############################################################################### Profile

    @cherrypy.expose
    def getProfile(self):
        lastUpdated = "00:00:00:00"
        fullname = "Lite W. Kim"
        position = "Student at the University of Auckland"
        description = "description"
        location = "location"
        picture = "https://scontent-syd2-1.xx.fbcdn.net/v/t1.0-1/p160x160/30653197_1478816908914193_2001747320223301632_n.jpg?_nc_cat=0&oh=e231c236754dafaf31ea6a88f6de63f3&oe=5B773B14"
        encoding = 0
        encryption = 0
        decryptionKey = "nokey"
    
############################################################################### I don't know what this is...
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

###############################################################################
# SEPERATOR                                                         SEPERATOR #
#                                  SEPERATOR                                  #
# SEPERATOR                                                         SEPERATOR #
###############################################################################

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
