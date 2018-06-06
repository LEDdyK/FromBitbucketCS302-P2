#!/usr/bin/python
""" cherrypy_example.py

    COMPSYS302 - Software Design
    Author: Andrew Chen (andrew.chen@auckland.ac.nz)
    Last Edited: 19/02/2018

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

import base64
import cherrypy
import hashlib
import json
import os
import re
import threading
import time
import urllib
import urllib2
import urlparse

# The address we listen for connections on
defURL = "http://cs302.pythonanywhere.com"
listen_ip = "172.23.154.65"
listen_port = 10001
#Through uni wifi
reportIP = "172.23.154.65"
reportLocation = "1"
#Through home wifi
#reportIP = "192.168.1.75"
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
# SEPARATOR                                                         SEPARATOR #
#                                  SEPARATOR                                  #
# SEPARATOR                                                         SEPARATOR #
###############################################################################

############################################################################### Main Page
 
    @cherrypy.expose
    def index(self):
        try:
            with open("images/" + cherrypy.session['username'] + ".jpg", "rb") as f:
                base64img = base64.b64encode(f.read())
            Page = '<head></head><body>'
            Page += "<div class=header><div class=serverstatus>server status:</div><div class=status>"+self.checkStatus()+"</div><div class=logout><a href=/signout>logout</a></div></div>"
            Page += "<div class=topsection></div>"
            Page += "<div class=dp><a href='/viewProfile?profile_username=" + cherrypy.session['username'] + "&sender=" + cherrypy.session['username'] + "&ip=" + listen_ip + "&port=" + str(listen_port) + "'>"
            Page += '<img src="data:image/jpeg;base64,' + base64img + '"></a></div>'
            Page += "<div class=welcome>Hello, " + cherrypy.session['username'] + "!<br></div>"
            Page += "<div class=textbody><div class=navigation>"
            Page += "<div class=dash><a href=/>dashboard</a></div>"
            Page += "<div class=users><a href=/>users</a></div>"
            Page += "<div class=groups><a href=/>groups</a></div>"
            Page += "<div class=messages><a href=/messages>messages</a></div></div>"
            Page += "<div class=bodybody><div class=board><div id=board_header>Global Message Board</div><div id=board_content>"+self.getBoard()
            Page += "</div></div><div class=latest><div id=latest_header>Latest Messages</div><div id=latest_content>"+self.getLatest()
            Page += "</div></div></div></div><div class=contacts>"
            Page += "<div id=contacts_header>contacts</div><div id=contacts_content>"
            Page += self.getonlineusers('username')
            Page += "</div></div>"
            #Test purposes
            Page += "<div>Test Message: "
            Page += globalTestMessage + "</div>"
            Page += "<div id=ip>" + listen_ip + "</div><div id=port>" + str(listen_port) + "</div>"
            Page += "</body>"
            Page += '<script language="javascript">'
            Page += open("jquery-3.3.1.min.js","r").read()
            Page += '</script><script language="javascript">'
            Page += open("pageMain.js","r").read()
            Page += '</script>'
            Page += open("test.css","r").read()
        except KeyError: #There is no username
            Page = "<body><div>Welcome!<br>"
            Page += "Click here to <a href='/login'>login</a>.</div></body>"
            Page += open("pageWelcome.css","r").read()
        return Page

    @cherrypy.expose
    #check the server status
    def checkStatus(self):
        API = "/listAPI"
        response = urllib2.urlopen(defURL + API)
        html = response.read()
        htmlLines = html.splitlines()
        firstLine = htmlLines[0].split(' ')
        if firstLine[0] == "Available":
            return " online"
        else:
            return " offline"

############################################################################### Messages Page

    @cherrypy.expose
    def messages(self):
        Page = '<head></head><body>'
        #Page += '<div class=userbuttons></div>
        Page += '<div class=formMessage>'
        Page += '<form action="/sendMessage">'
        Page += 'Receiver (username):<br>'
        Page += '<input type="text" name="receiver"><br>'
        Page += 'Message:<br>'
        Page += '<input type="text" name="message"><br><br>'
        Page += '<input type="submit" value="send"><br>'
        Page += '</form></div><br><br><br><br>'
        Page += '<div class=formFile>'
        Page += '<form action="/sendFile">'
        Page += 'Receiver (username):<br>'
        Page += '<input type="text" name="receiver"><br>'
        Page += 'filename:<br>'
        Page += '<input type="text" name="filename"><br>'
        Page += 'filepath:<br>'
        Page += '<input type="text" name="filepath"><br>'
        Page += 'filetype:<br>'
        Page += '<input type="text" name="filetype"><br>'
        Page += '<input type="submit" value="send"><br>'
        Page += '</form>'
        Page += '</div>'
        Page += '<div id="contacts_content"></div>'
        Page += '</body>'
        Page += '<script language="javascript">'
        Page += open("jquery-3.3.1.min.js","r").read()
        Page += '</script><script language="javascript">'
        Page += open("test2.js","r").read()
        Page += '</script>'
        return Page

############################################################################### Login (to server) <<tested and works>>
    
    @cherrypy.expose
    #logging in to the login server
    def login(self):
        Page = '<body><form action="/signin" method="post" enctype="multipart/form-data">'
        Page += '<div class=username>Username:<br><input type="text" name="username"/></div>'
        Page += '<div class=password>Password:<br><input type="text" name="password"/>'
        Page += '<input class=login type="submit" value="Login"/></form></div></body>'
        Page += open("pageLogin.css","r").read()
        return Page
    
    @cherrypy.expose
    #logging global variables
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
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login')
    
    #TODO
    """Allowing this only allows the user lkim564 to login through this script
    Adjust so that anyone may log in"""
    def authoriseUserLogin(self, username, password):
        hashedPass = hashlib.sha256(str(password+username)).hexdigest()
        if (username == "lkim564") and (hashedPass == "d9174a05cbe8d7707c53d7d5b78ce6190cd65a8f0fbc849dc966d962a88302e3"):
            return 0
        else:
            return 1

############################################################################### Logout (from server) <<tested and works>>

    @cherrypy.expose
    def signout(self):
        global globalAutoReport
        """Logs the current user out, expires their session"""
        API = "/logoff"
        username = "?username=" + globalUsername
        password = "&password=" + globalHashedPass
        enc = ""
        globalAutoReport = False
        if (username == None):
            pass
        else:
            response = urllib2.urlopen(defURL + API + username + password + enc)
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

############################################################################### Get users (from server) <<tested and works>>

    @cherrypy.expose
    def make_buttons(self):
        userList = self.getallusers().split('<br>')
        Page = ''
        Page += '<body>'
        Page += "<div id=ip>" + listen_ip + "</div><div id=port>" + str(listen_port) + "</div>"
        for i in range (0, len(userList)-1):
            Page += '<button id=' + userList[i] + ' type="button" onclick="autofill()" disabled>' + userList[i] + '</button><br>'
        Page += '<div class=test>testing</div>'
        Page += '</body>'
        Page += '<script language="javascript">'
        Page += open("jquery-3.3.1.min.js","r").read()
        Page += '</script><script language="javascript">'
        Page += open("messages.js","r").read()
        Page += '</script>'
        return Page

############################################################################### Get users (from server) <<tested and works>>

    @cherrypy.expose
    def getallusers(self):
        #open url
        API = "/listUsers"
        response = urllib2.urlopen(defURL + API)
        #get url contents
        html = response.read()
        response.close()
        html = self.cleanHTML(html)
        htmlUsers = html.split(',')
        htmlUsers.sort()
        #display url contents
        Page = ''
        for i in htmlUsers:
            Page += i
            Page += '<br>'
        return Page
        
    @cherrypy.expose
    def getonlineusers(self,item):
        #open url
        API = "/getList"
        username = "?username=" + cherrypy.session['username']
        password = "&password=" + cherrypy.session['hashedPass']
        response = urllib2.urlopen(defURL + API + username + password)
        #get url contents
        html = response.read()
        response.close()
        html = self.cleanHTML(html)
        if item == 'all':
            return html
        htmlLines = html.splitlines()
        #display url contents
        Page = ''
        saveList = open("server/getList.txt","w+")
        saveList.write(html)
        for i in range(1,len(htmlLines)):
            user = htmlLines[i].split(',')
            if user[0] != cherrypy.session['username']:
                if item == 'username':
                    Page += user[0]
                    Page += '<br>'
                elif item == 'location':
                    Page += user[1]
                    Page += '<br>'
                elif item == 'ip':
                    Page += user[2]
                    Page += '<br>'
                elif item == 'port':
                    Page += user[3]
                    Page += '<br>'
                elif item == 'time':
                    Page += user[4]
                    Page += '<br>'
                elif item == 'pubKey':
                    try:
                        Page += user[5]
                    except:
                        Page += 'Key Unavailable'
                    Page += '<br>'
        return Page

############################################################################### Report (to server) <<tested and works>>
    
    def initReport(self):
        global background
        self.serverReport()
        #setup online report thread (run every 10 seconds)
        background = threading.Timer(10, self.backgroundReport)
        background.start()
        getPros = threading.Timer(60, self.getProBack())
        getPros.start()
    
    def serverReport(self):
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
            #run this every 10 seconds
            time.sleep(10)
            try:
                stillOnline = urllib2.urlopen('http://'+listen_ip+':'+str(listen_port)+'/getOnline').read()
                if stillOnline != "0":
                    self.signout()
            except:
                self.signout()

    @cherrypy.expose
    def getOnline(self):
        return "0"
                

############################################################################### Receive messages (from users) <<tested and works>>

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self, globalMessage="0"):
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
        if globalMessage == "0":
            #check messaging rate first. Set the limit as 7 messages per minute
            checkRate = self.limitRate(sender, '7', stamp)
            if checkRate == "11":
                #If limit has been reached, return to the user the rate limit error code (11)
                return checkRate
            #append appropriate message file (by sender)
            self.appendFile(str(stamp), sender, message)
        else:
            #append global message file
            messageFile = open("messages/1111.txt",'r')
            temp = messageFile.read()
            messageFile.close()
            messageFile = open("messages/1111.txt",'w+')
            messageFile.write(str(stamp) + "\n" + message + "\nsender: " + sender + "\n\n")
            messageFile.write(temp)
            messageFile.close()
        return "0"

############################################################################### Append message (to my database)

    def appendFile(self, stamp, sender, message):
        stamp = self.cleanHTML(stamp)
        sender = self.cleanHTML(sender)
        message = self.cleanHTML(message)
        messageFile = open("messages/" + sender + ".txt",'a+')
        messageFile.write("stamp: "+stamp+"[[separator]]message: "+message+"[[separator]]sender: "+sender+"[[separatorEND]]") 
        messageFile.close()
        latest = open("messages/0000.txt",'r')
        segments = latest.read().split('[[INITseparator]]')
        latest.close()
        value = int(segments[0])
        if value == 0:
            value = 1
            latest = open("messages/0000.txt",'w')
            latest.write(str(value)+"[[INITseparator]]stamp: "+stamp+"[[separator]]message: "+message+"[[separator]]sender: "+sender+"[[separatorEND]]")
        else:
            value += 1
            #copy contents to temp (split_contents)
            latest = open("messages/0000.txt",'r')
            split_contents = latest.read().split('[[INITseparator]]')
            latest.close()
            #overwrite with value first then new message then copied contents
            latest = open("messages/0000.txt",'w')
            if value < 11:
                # value + new message + copied message(s)
                latest.write(str(value)+"[[INITseparator]]stamp: "+stamp+"[[separator]]message: "+message+"[[separator]]sender: "+sender+"[[separatorEND]]"+split_contents[1])
            else:
                # value + new message
                latest.write("10[[INITseparator]]stamp: "+stamp+"[[separator]]message: "+message+"[[separator]]sender: "+sender+"[[separatorEND]]")
                latest.close()
                # + 9 latest messages (remove the oldest)
                contents = split_contents[1].split("[[separatorEND]]")
                latest = open("messages/0000.txt",'a')
                for i in range (0,9):
                    latest.write(contents[i]+"[[separatorEND]]")
        latest.close()

############################################################################### Get latest messages (from my database)

    @cherrypy.expose
    def getLatest(self):
        latest = open("messages/0000.txt",'r')
        first_split = latest.read().split('[[INITseparator]]')
        latest.close()
        sec_split = first_split[1].split('[[separatorEND]]')
        output = ''
        for i in range (0,int(first_split[0])):
            lines = sec_split[i].split('[[separator]]')
            output += lines[0] + "<br>"
            output += self.embbedObjects(lines[1],False)
            output += lines[1] + "<br>" + lines[2] + "<br><br>"
        return output

############################################################################### Embbed pictures/audio/video/pdf

    def embbedObjects(self,line,condition):
        output = ''
        if "{{file/type=" in line:
            file_split1 = line.split('file/type=')
            file_split2 = file_split1[1].split('}}{{')
            mime = file_split2[0]
            tp = mime.split('/')[0]
            ex = mime.split('/')[1]
            file_split3 = file_split2[1].split('}}')
            path = file_split3[0]
            with open(path, "rb") as f:
                base64file = base64.b64encode(f.read())
            if tp == 'image':
                output += '<img src="data:'+mime+';base64,'+base64file+'"><br>'
            #The following should only be allowed if the section does not refresh itself (condition = true if no refresh)
            elif condition:
                if tp == 'audio':
                    output += '<audio controls><source src="data:'+mime+';base64,'+base64file+'"></audio><br>'
                elif tp == 'video':
                    output += '<video width="580" controls><source src="data:'+mime+';base64,'+base64file+'"></video><br>'
                elif mime == 'application/pdf':
                    output += '<iframe "width:580" src="data:'+mime+';base64,'+base64file+'"><br>'
        return output

############################################################################### Get global messages (from my database)

    @cherrypy.expose
    def getBoard(self):
        latest = open("messages/1111.txt",'r')
        lines = latest.read().splitlines()
        latest.close()
        output = ''
        for i in range (0,len(lines)):
            output += lines[i] + "<br>"
        return output
        
############################################################################### Receive files (from users) <<tested and works>>

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self):
        input_dict = cherrypy.request.json
        sender = input_dict['sender']
        destination = input_dict['destination']
        base64file = input_dict['file']
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
        #check messaging rate first. Set the limit as 7 messages per minute
        checkRate = self.limitRate(sender, '7', stamp)
        if checkRate == "11":
            #If limit has been reached, return to the user the rate limit error code (11)
            return checkRate
        #append appropriate message file (by sender) with file tag
        self.appendFile(str(stamp), sender, "{{file/type="+content_type+"}}{{messages/receivedfiles/"+filename+"}}")
        item = base64.b64decode(base64file)
        f = open("messages/receivedfiles/"+filename,'wb')
        f.write(item)
        f.close()
        return "0"
        
############################################################################### Send messages (to users) <<tested and works>>
   
    @cherrypy.expose
    def sendMessage(self,receiver,message):
        alldetails = self.getonlineusers('all')
        individuals = alldetails.splitlines()
        for i in range (1,len(individuals)):
            detail = individuals[i].split(',')
            if receiver == detail[0]:
                ip = detail[2]
                port = detail[3]
                
        output_dict = {
            "sender":cherrypy.session['username'],
            "destination":receiver,
            "message":message,
            "stamp":time.time()
            }
        data = json.dumps(output_dict)
        req = urllib2.Request("http://"+ip+":"+port+"/receiveMessage", data, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)
        raise cherrypy.HTTPRedirect('/messages')

############################################################################### Send files (to users) <<tested and works>>

    @cherrypy.expose
    def sendFile(self,receiver,filename,filepath,filetype):
        alldetails = self.getonlineusers('all')
        individuals = alldetails.splitlines()
        for i in range (1,len(individuals)):
            detail = individuals[i].split(',')
            if receiver == detail[0]:
                ip = detail[2]
                port = detail[3]
        with open(filepath, "rb") as f:
            base64file = base64.b64encode(f.read())
        output_dict = {
            "sender":cherrypy.session['username'],
            "destination":receiver,
            "file":base64file,
            "filename":filename,
            "content_type":filetype,
            "stamp":time.time()
            }
        data = json.dumps(output_dict)
        req = urllib2.Request("http://"+ip+":"+port+"/receiveFile", data, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)
        raise cherrypy.HTTPRedirect('/messages')

############################################################################### Give profile (to users) <<tested and works>>

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getProfile(self):

        input_dict = cherrypy.request.json
        profile_username = input_dict['profile_username']
        sender = input_dict['sender']
        
        proFile = open("server/profile/"+profile_username+".txt", "r")
        proFileSeg = proFile.read().split('>>')
        proFile.close()
        fullname = proFileSeg[1]
        position = proFileSeg[3]
        description = proFileSeg[5]
        location = proFileSeg[7]
        picture = proFileSeg[9]
        encoding = 0
        encryption = 0
        decryptionKey = "nokey"
        lastUpdated = proFileSeg[11]
        output_dict = {
            "lastUpdated":lastUpdated,
            "fullname":fullname,
            "position":position,
            "description":description,
            "location":location,
            "picture":picture,
            "encoding":encoding,
            "encryption":encryption,
            "decryptionKey":decryptionKey
            }
        data = json.dumps(output_dict)
        return data

############################################################################### View profile <<tested and works>>

    @cherrypy.expose
    def viewProfile(self,profile_username,sender,ip,port):

        output_dict = {
            "profile_username":profile_username,
            "sender":sender
            }
        
        data = json.dumps(output_dict)
        req = urllib2.Request("http://"+ip+":"+port+"/getProfile", data, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)
        input_dict = json.loads(response.read())
        try:
            lastUpdated = input_dict['lastUpdated']
        except:
            lastUpdated = "no stamp"
        try:
            fullname = input_dict['fullname']
        except KeyError:
            fullname = "no name"
        try:
            position = input_dict['position']
        except KeyError:
            position = "no position"
        try:
            description = self.cleanHTML(input_dict['description'])
            try:
                desLines = description.split('\n')
                newDes = ''
                for i in desLines:
                    newDes += i + '<br>'
            except:
                newDes = ''
        except KeyError:
            description = "no description"
        try:
            location = input_dict['location']
        except KeyError:
            location = "nolocation"
        try:
            picture = input_dict['picture']
        except KeyError:
            picture = "nopicture"
        try:
            encoding = input_dict['encoding']
        except KeyError:
            encoding = 0
        try:
            encryption = input_dict['encryption']
        except KeyError:
            encryption = 0
        try:
            decryptionKey = input_dict['decryptionKey']
        except KeyError:
            decryptionKey = "nokey"
        Page = "<body>"
        Page += "<div class=fullname><div id=fullname_header>Fullname</div><div id=fullname_content>"+self.cleanHTML(fullname)+"</div></div>"
        Page += "<div class=position><div id=position_header>Position</div><div id=position_content>"+self.cleanHTML(position)+"</div></div>"
        Page += "<div class=description><div id=description_header>Description</div><div id=description_content>"+newDes+"</div></div>"
        Page += "<div class=location><div id=location_header>Location</div><div id=location_content>"+self.cleanHTML(location)+"</div></div>"
        Page += '<div class=picture><div id=picture_header>Picture</div><div id=picture_content><img src="'+self.cleanHTML(picture)+'"></div></div>'
        Page += "</body>"
        Page += open("profile.css").read()
        return Page

############################################################################### Auto get other profile data

    def getProBack(self):
        while globalAutoReport
        html = self.getonlineusers('all')
        htmlLines = html.splitlines()
        for i in range (1,len(htmlLines)):
            details = htmlLines[i].split(',')
            try:
                self.getProfileData(details[0],cherrypy.session['username'],details[2],details[3])
            except:
                error = 'cannot obtain profile'
        time.sleep(60)


############################################################################### get other profiles (to my database)

    @cherrypy.expose
    def getProfileData(self,profile_username,sender,ip,port):
        output_dict = {
            "profile_username":profile_username,
            "sender":sender
            }
        data = json.dumps(output_dict)
        req = urllib2.Request("http://"+ip+":"+port+"/getProfile", data, {'Content-Type':'application/json'})
        response = urllib2.urlopen(req)
        f = open("server/profile/" + profile_username + ".txt",'w+')
        input_dict = json.loads(response.read())
        try:
            lastUpdated = input_dict['lastUpdated']
        except:
            lastUpdated = "no stamp"
        try:
            fullname = input_dict['fullname']
        except:
            fullname = "no name"
        try:
            position = input_dict['position']
        except:
            position = "no position"
        try:
            description = input_dict['description']
        except:
            description = "no description"
        try:
            location = input_dict['location']
        except:
            location = "nolocation"
        try:
            picture = input_dict['picture']
        except:
            picture = "nopicture"
        try:
            encoding = input_dict['encoding']
        except:
            encoding = 0
        try:
            encryption = input_dict['encryption']
        except:
            encryption = 0
        try:
            decryptionKey = input_dict['decryptionKey']
        except:
            decryptionKey = "nokey"
        f.write("<<fullname>>"+str(fullname)+">>\n<<position>>"+str(position)+">>\n<<description>>"+str(description)+">>\n<<location>>"+str(location)+">>\n<<picture>>"+str(picture)+"<<lastUpdated>>"+lastUpdated)
        f.close()

############################################################################### Clean input (no HTML tags)

    def cleanHTML(self,text):
        """#Completely eliminate anything within angle brackets along with the angle brackets
        cleanr = re.compile('<.*?>')
        cleantext = re.sub(cleanr, '', text)
        return cleantext"""
        #Alternatively: Just replace the angle brackets with HTML recognisable string representations of angle brackets
        first = text.replace("<", "&lt;")
        second = first.replace(">","&gt;")
        return second

############################################################################### Rate limiting

    def limitRate(self, sender, limit, stamp):
        #don't let anyone send you more than 7 messages within a minute
        #return 0 if limit not reached, else return 1
        try:
            messageFile = open('messages/'+sender+'.txt','r').read()
        except:
            #if there is no existing file, then this is the first line of conversation and does not require limiting
            return "0"
        splitMessages = messageFile.split('[[separatorEND]]')
        #if there are less than limit, free pass
        if len(splitMessages) < int(limit):
            return "0"
        #else the limit has been reached
        monitorMessage = splitMessages[len(splitMessages)-int(limit)-1]
        monitorStamp = monitorMessage.split('[[separator]]')
        justStamp = float(monitorStamp[0].split(" ")[1])
        #compare if current time is less than 60s + message sent (limit) times ago
        if float(stamp) < (justStamp+60):
            #conveniently return the error code
            return "11"
        #else more than a minute has passed and allow new message
        return "0"

############################################################################### Give ping (to users)

    @cherrypy.expose
    def ping(self):
        return "0"

###############################################################################
# SEPARATOR                                                         SEPARATOR #
#                                  SEPARATOR                                  #
# SEPARATOR                                                         SEPARATOR #
###############################################################################

############################################################################### /getList (from my database)

    @cherrypy.expose
    def getList(self, json_format="0"):
        try:
            getList = open("server/getList.txt", "r")
        except:
            return "file not found"
        if json_format == "1":
            htmlLines = getList.read().splitlines()
            output_dict = {}
            for i in range(1,len(htmlLines)):
                users = htmlLines[i].split(',')
                """entry = {
                    "username"+str(i):users[0],
                    "location"+str(i):users[1],
                    "ip"+str(i):users[2],
                    "port"+str(i):users[3],
                    "last login in epoch time"+str(i):users[4]
                    }
                if len(users)>5:
                    entry.update({"publicKey"+str(i):users[5]})"""
                entry = {
                    users[0]:htmlLine[i]
                    }
                output_dict.update(entry)
            return json.dumps(output_dict)
        else:
            return getList.read()

############################################################################### /report (to my database)

    @cherrypy.expose
    def report(self, username, passphrase, signature, location, ip, port, encryption="0"):
        return "report"

############################################################################### /logoff (from my database)

    @cherrypy.expose
    def logoff(self, username, passphrase, signature, encryption="0"):
        return "logoff"
    
############################################################################### I don't know what this is for...
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

###############################################################################
# SEPARATOR                                                         SEPARATOR #
#                                  SEPARATOR                                  #
# SEPARATOR                                                         SEPARATOR #
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
