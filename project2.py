"""
COMPSYS 302
Python Project
Author: Lite Kim
Institution: The University of Auckland
UPI: lkim564
ID: 6773928

The following uses CherryPy 3.2.2
On Python 2.7
"""
# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10001

import cherrypy
import urllib2
import hashlib

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
        Page = "Welcome! This is a test website for COMPSYS302!<br/>"
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Here is some bonus text because you've logged in!"
        except KeyError: #There is no username
            Page += "Click here to <a href='login'>login</a>."
        return Page

    @cherrypy.expose
    def login(self):
        Page = '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = self.authoriseUserLogin(username,password)
        if (error == 0):
            cherrypy.session['username'] = username;
            hashedPass = hashlib.sha256(str(password+username)).hexdigest()
            #open url
            response = urllib2.urlopen('http://cs302.pythonanywhere.com/getList?username=' + username + '&password=' + hashedPass)
            #get url contents
            html = response.read()
            #display url contents
            Page = html
            return Page
        else:
            raise cherrypy.HTTPRedirect('/logintest')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if (username == None):
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

    def authoriseUserLogin(self, username, password):
        hashedPass = hashlib.sha256(str(password+username)).hexdigest()
        if (username == "lkim564") and (hashedPass == "d9174a05cbe8d7707c53d7d5b78ce6190cd65a8f0fbc849dc966d962a88302e3"):
            return 0
        else:
            return 1
