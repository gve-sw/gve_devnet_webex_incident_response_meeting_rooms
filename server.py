#!/usr/bin/env python
#  -*- coding: utf-8 -*-
"""
Copyright (c) 2021 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

This sample script leverages the Flask web service micro-framework
(see http://flask.pocoo.org/).  By default the web server will be reachable at
port 5500 you can change this default if desired (see `app.run(...)`).

"""

from dotenv import load_dotenv

__author__ = "Gerardo Chaves"
__author_email__ = "gchaves@cisco.com"
__copyright__ = "Copyright (c) 2016-2022 Cisco and/or its affiliates."
__license__ = "Cisco"

from requests_oauthlib import OAuth2Session

from flask import Flask, request, redirect, session, url_for, render_template, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
import requests
import os
import time
import json
import jinja2

from webexteamssdk import WebexTeamsAPI, Webhook, AccessToken

# load all environment variables
load_dotenv()



AUTHORIZATION_BASE_URL = 'https://api.ciscospark.com/v1/authorize'
TOKEN_URL = 'https://api.ciscospark.com/v1/access_token'
SCOPE = 'spark:all'
ADMIN_SCOPE = ['spark-admin:people_read', 'spark-admin:telephony_config_read', 'spark-admin:organizations_read' , 'spark-admin:roles_read']

DISABLE_SSL_VERIFY=False

#initialize variables for URLs
#REDIRECT_URL must match what is in the integration, but we will construct it below in __main__
# so no need to hard code it here
PUBLIC_URL='http://0.0.0.0:5500'
REDIRECT_URI=""

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize the environment
# Create the web application instance
app = Flask(__name__)

#SQLAlchemy
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incident_resp_db.sqlite3'
db = SQLAlchemy(app)

member_identifier = db.Table('member_identifier',
    db.Column('spaces_id', db.Integer, db.ForeignKey('spaces.spaces_id')),
    db.Column('responders_id', db.Integer, db.ForeignKey('responders.responders_id'))
)

class Responders(db.Model):
    __tablename__ = 'responders'
    responders_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    wbxpersonID = db.Column(db.String(255))
    email = db.Column(db.String(255))
    mobilenumber = db.Column(db.String(255))
    voicenumber = db.Column(db.String(255))
    sendSMS = db.Column(db.Boolean)
    sendVoice = db.Column(db.Boolean)


class Spaces(db.Model):
    __tablename__ = 'spaces'
    spaces_id = db.Column(db.Integer, primary_key=True)
    incidentname = db.Column(db.String(255))
    wbxspaceID = db.Column(db.String(255), nullable=False)
    responders = db.relationship("Responders",
                               secondary=member_identifier)

# will not create tables if already there
db.create_all()

app.secret_key = '123456789012345678901234'
#api = WebexTeamsAPI(access_token=TEST_TEAMS_ACCESS_TOKEN)
api = None

@app.route("/")
def login():
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Webex Teams)
    using a URL with a few key OAuth parameters.
    """
    global REDIRECT_URI
    global PUBLIC_URL

    # trigger a full oAuth flow with user intervention
    REDIRECT_URI = PUBLIC_URL + '/callback'  # Copy your active  URI + /callback
    print("Using PUBLIC_URL: ",PUBLIC_URL)
    print("Using redirect URI: ",REDIRECT_URI)
    teams = OAuth2Session(os.getenv('CLIENT_ID'), scope=SCOPE, redirect_uri=REDIRECT_URI)
    authorization_url, state = teams.authorization_url(AUTHORIZATION_BASE_URL)

    # State is used to prevent CSRF, keep this for later.
    print("Storing state: ",state)
    session['oauth_state'] = state
    print("root route is re-directing to ",authorization_url," and had sent redirect uri: ",REDIRECT_URI)
    return redirect(authorization_url)

def check_token_refresh(tokens):
    print("Existing token on file, checking if expired....")
    access_token_expires_at = tokens['expires_at']
    if time.time() > access_token_expires_at:
        print("expired!")
        refresh_token = tokens['refresh_token']
        # make the calls to get new token
        extra = {
            'client_id': os.getenv('CLIENT_ID'),
            'client_secret': os.getenv('CLIENT_SECRET'),
            'refresh_token': refresh_token,
        }
        auth_code = OAuth2Session(os.getenv('CLIENT_ID'), token=tokens)
        new_teams_token = auth_code.refresh_token(TOKEN_URL, **extra)
        print("Obtained new_teams_token: ", new_teams_token)
        # assign new token
        tokens = new_teams_token
        # store away the new token
        with open('tokens.json', 'w') as json_file:
            json.dump(tokens, json_file)
    return tokens

@app.route("/admin_login")
def admin_login():
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Webex Teams)
    using a URL with a few key OAuth parameters.
    """
    global REDIRECT_URI
    global PUBLIC_URL

    if os.path.exists('tokens.json'):
        with open('tokens.json') as f:
            tokens = json.load(f)
    else:
        tokens = None

    if tokens == None or time.time()>(tokens['expires_at']+(tokens['refresh_token_expires_in']-tokens['expires_in'])):
        # We could not read the token from file or it is so old that even the refresh token is invalid, so we have to
        # trigger a full oAuth flow with user intervention
        REDIRECT_URI = PUBLIC_URL + '/callback'  # Copy your active  URI + /callback
        print("Using PUBLIC_URL: ",PUBLIC_URL)
        print("Using redirect URI: ",REDIRECT_URI)
        teams = OAuth2Session(os.getenv('CLIENT_ID'), scope=ADMIN_SCOPE, redirect_uri=REDIRECT_URI)
        authorization_url, state = teams.authorization_url(AUTHORIZATION_BASE_URL)

        # State is used to prevent CSRF, keep this for later.
        print("Storing state: ",state)
        session['oauth_state'] = state
        print("root route is re-directing to ",authorization_url," and had sent redirect uri: ",REDIRECT_URI)
        return redirect(authorization_url)
    else:
        # We read a token from file that is at least younger than the expiration of the refresh token, so let's
        # check and see if it is still current or needs refreshing without user intervention
        validated_tokens=check_token_refresh(tokens)
        session['oauth_token'] = validated_tokens
        print("Using stored or refreshed token....")
        return redirect(url_for('.started'))

# Step 2: User authorization, this happens on the provider.

@app.route("/callback", methods=["GET"])
def callback():
    """
    Step 3: Retrieving an access token.
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    global REDIRECT_URI

    print("Came back to the redirect URI, trying to fetch token....")
    print("redirect URI should still be: ",REDIRECT_URI)
    print("Calling OAuth2SEssion with CLIENT_ID ",os.getenv('CLIENT_ID')," state ",session['oauth_state']," and REDIRECT_URI as above...")
    auth_code = OAuth2Session(os.getenv('CLIENT_ID'), state=session['oauth_state'], redirect_uri=REDIRECT_URI)
    print("Obtained auth_code: ",auth_code)
    print("fetching token with TOKEN_URL ",TOKEN_URL," and client secret ",os.getenv('CLIENT_SECRET')," and auth response ",request.url)
    token = auth_code.fetch_token(token_url=TOKEN_URL, client_secret=os.getenv('CLIENT_SECRET'),
                                  authorization_response=request.url)

    print("Token: ",token)
    print("should have grabbed the token by now!")
    session['oauth_token'] = token

    return redirect(url_for('.started'))

@app.route("/started", methods=["GET"])
def started():

    # Use returned token to make Teams API calls for information on user, list of spaces and list of messages in spaces
    global api

    teams_token = session['oauth_token']
    api = WebexTeamsAPI(access_token=teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)

    # first retrieve information about who is logged in
    theResult=api.people.me()
    #print("TheResult calling api.people.me(): ",theResult)


    #TODO: Test actually going to /admin_login!!! if it still does not work,
    # Need to try a call that would only work for an admin and handle error
    if theResult.roles:
        # it was an admin who logged in, so let's capture that token into a file for
        # use by moderators to be able to read the entire directory since they cannot with
        # their own credentials
        with open('tokens.json', 'w') as json_file:
            json.dump( session['oauth_token'], json_file)
        return render_template("admin_login_success.html", moderatorURL=PUBLIC_URL)

    if os.path.exists('tokens.json'):
        with open('tokens.json') as f:
            admin_tokens = json.load(f)
    else:
        admin_tokens = None

    if admin_tokens == None or time.time()>(admin_tokens['expires_at']+(admin_tokens['refresh_token_expires_in']-admin_tokens['expires_in'])):
        # We could not read the token from file or it is so old that even the refresh token is invalid, so we have to
        # trigger a full oAuth flow with user intervention
        print("Need to have admin login go generate admin token....")
        return render_template("need_admin_login.html", adminURL=PUBLIC_URL+'/admin_login')
    else:
        # We read a token from file that is at least younger than the expiration of the refresh token, so let's
        # check and see if it is still current or needs refreshing without user intervention
        validated_admin_tokens=check_token_refresh(admin_tokens)
        print("Admin token to use now stored in validated_admin_tokens")

    #store away the admin token in the session to use later
    session['adminToken'] = validated_admin_tokens

    #store the Webex Person ID of the owner of this session, which should be a moderator in the space
    modID=theResult.id
    session['modID'] = modID

    #retrieve memberships to see which spaces this user is a moderator of
    theMemberships=api.memberships.list()

    moderatedRooms=[]
    for membership in theMemberships:
        if membership.isModerator:
            roomId=membership.roomId
            theRoom=api.rooms.get(roomId)
            theRoomTitle=theRoom.title
            moderatedRooms.append({'id':roomId,'title':theRoomTitle})

    #print(moderatedRooms)
    return render_template("select_space.html", moderatorName=theResult.displayName , moderatedRooms=moderatedRooms)


@app.route("/space_selected" , methods=['GET', 'POST'])
def space_selected(operation=None):
    if operation==None:
        roomID = str(request.form.get('space_select'))
    else:
        roomID=session['roomID']

    print(roomID)
    global api

    #retrieve token from session
    teams_token = session['oauth_token']

    #retieve teamID we are working with
    #teamID=session['teamID']

    #store away the roomID we are working on at the moment
    session['roomID'] = roomID
    api = WebexTeamsAPI(access_token=teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)

    theRoom=api.rooms.get(roomID)
    space_name=theRoom.title

    #retrieve members of the space
    theMemberships=api.memberships.list(roomId=roomID)

    # load space info from the 'spaces' table indexed on the webex ID of the room. If not there, create and commit and entry
    # for it in the 'spaces' table. This will be the_space.
    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()
    if the_space==None:
        the_space = Spaces(incidentname='', wbxspaceID=roomID)
        db.session.add(the_space)

    #initialize a list of Webex IDs of all persons in the webex space
    memberIDs=[]

    #iterate theMember in theMemberships
    for theMember in theMemberships:
        found=False
        for a_responder in the_space.responders:
            # if theMember is also one of the responders of the_space by comparing email address
            # but the responder does not have a webex person ID,
            # then copy WbxID and Name from theMember into that responder and update responders table with it.
            # if it does have a webex person ID then we are good, we just mark it as found and move on
            if a_responder.email==theMember.personEmail:
                found=True
                if a_responder.wbxpersonID=="":
                    a_responder.wbxpersonID=theMember.personId
                    a_responder.name=theMember.personDisplayName
            # if also one of the responders of the_space by comparing WbxIDs, take no action


        #if a webex space member not found as a responder in the_space in the DB by either email of WbxID, then
        # look for it in the entire responders table.
        if not found:
            another_responder=Responders.query.filter_by(wbxpersonID=theMember.personId).first()
            # if not there, create a new one
            if another_responder==None:
                #add phone number below as per the Webex person object if there and
                # if user is in the same org of that person and has right to see phone numbers
                the_person = api.people.get(theMember.personId)
                # pull mobile phone info from the person object to add to DB if available
                the_person_mobile = None
                the_person_voice = None
                sms_type = os.getenv('INT_PHONE_TYPE_SMS')
                voice_type = os.getenv('INT_PHONE_TYPE_VOICE')
                if the_person.phoneNumbers():
                    for aNumber in the_person.phoneNumbers():
                        if aNumber['type'] == sms_type:  # i.e. "mobile":
                            the_person_mobile = aNumber['value']
                        if aNumber['type'] == voice_type:  # i.e. "work":
                            the_person_voice = aNumber['value']

                another_responder = Responders(wbxpersonID=theMember.personId,
                                               name=theMember.personDisplayName,
                                               email=theMember.personEmail,
                                               mobilenumber=the_person_mobile,
                                               voicenumber=the_person_voice,
                                               sendSMS=False,
                                               sendVoice=False)
                db.session.add(another_responder)
            # add it to the_space (either newly created or if found)
            the_space.responders.append(another_responder)

    #add the person ID being processed to our list to clean out the_space later:
        memberIDs.append(theMember.personId)

    #commit DB changes
    db.session.commit()

    #iterate through all responders in the_space
    for the_responder in the_space.responders:
    # remove any member from the_space that is not in the Webex space and have a WebexID (if they do not have
    # a WebexID they should have at least an SMS or a voice number to keep them around as PSTN only entries, but we won't validate)
        if the_responder.wbxpersonID!=None:
            if the_responder.wbxpersonID  not in memberIDs:
                the_space.responders.remove(the_responder)



    #commit DB changes
    db.session.commit()

    #initialize list to send to page with members of space
    members=[]

    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()
    for a_responder in the_space.responders:
        members.append({'memberId':a_responder.responders_id,
                        'memberEmail':a_responder.email,
                        'memberDisplayName':a_responder.name,
                        'memberMobile': a_responder.mobilenumber if a_responder.mobilenumber!=None else "",
                        'memberVoice': a_responder.voicenumber if a_responder.voicenumber!=None else "",
                        'personInitials': ''.join(i[0] for i in a_responder.name.split()).upper(),
                        'sendSMS' : a_responder.sendSMS,
                        'sendVoice' : a_responder.sendVoice
                        })

    #initialize list to send to page with externals
    externals=[]
    the_ext_responders=Responders.query.filter_by(wbxpersonID=None)
    for ext_responder in the_ext_responders:
        externals.append({'extID':ext_responder.responders_id,
                        'extName':ext_responder.name,
                        'extMobile':ext_responder.mobilenumber,
                        'extVoice': ext_responder.voicenumber,
                        'extEmail': ext_responder.email,
                        'personInitials': ''.join(i[0] for i in ext_responder.name.split()).upper()
                        })


    #Fill available responders to select from or directory
    admin_teams_token=session['adminToken']
    adminApi = WebexTeamsAPI(access_token=admin_teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)

    # only trigger partial search if a search term was passed in variable operation and is at least
    # three characters long since the people.list() method requires it
    if (operation!=None and operation[:7]=='search:' and len(operation)>10 ):
        fullDirectory=adminApi.people.list(displayName=operation.split('search:',1)[1])
    else:
        fullDirectory=adminApi.people.list()

    team=[]
    for entry in fullDirectory:
        entryPhoneMobile=''
        entryPhoneVoice = ''
        sms_type = os.getenv('INT_PHONE_TYPE_SMS')
        voice_type = os.getenv('INT_PHONE_TYPE_VOICE')
        if entry.phoneNumbers():
            for aNumber in entry.phoneNumbers():
                print(f"Numbers found for {entry.displayName}: {aNumber['type']} {aNumber['value']} ")
                if aNumber['type'] == sms_type:
                    entryPhoneMobile = aNumber['value']
                if aNumber['type'] == voice_type:
                    entryPhoneVoice = aNumber['value']

        team.append({'personId':entry.id,
                        'personEmail':entry.emails[0],
                        'personDisplayName':entry.displayName,
                        'personInitials': ''.join(i[0] for i in entry.displayName.split()).upper(),
                        'personPhoneMobile': entryPhoneMobile,
                        'personPhoneVoice': entryPhoneVoice
                        })

    return render_template("index.html",team=team, space_name=space_name, inc_name=the_space.incidentname, members=members, externals=externals, smsorigin=os.getenv('SMS_ORIGIN'))


@app.route("/start_conference", methods=['GET', 'POST'])
def start_conference():
    global api

    # retrieve token from session
    teams_token = session['oauth_token']

    # retrieve roomID we are working with
    roomID = session['roomID']

    #retrieve the Webex Person ID of the owner of this session, which should be a moderator in the space
    modID=session['modID']


    api = WebexTeamsAPI(access_token=teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)

    # obtain incident name from arguments
    formIncidentName = request.args.get('inc_name', '')

    print("Incident name from form: ",formIncidentName)

    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()

    if the_space != None:
        if formIncidentName!=the_space.incidentname:
            the_space.incidentname=formIncidentName
            db.session.commit()

    theIncidentName=the_space.incidentname

    #obtain the meeting information for the room.
    rmMtgInfo=api.rooms.get_meeting_info(roomID)

    theWebexSpace=api.rooms.get(roomID)


    #assemble message
    msgSnd=f'Join incident “{theIncidentName}” being handled in response room {theWebexSpace.title}.\
    Options (just use one):\n\
    Via Webex App: {rmMtgInfo.meetingLink}\n\
    Dial into the meeting: {rmMtgInfo.callInTollNumber}pp{rmMtgInfo.meetingNumber}# (press # again when prompted)'

    print(msgSnd)

    #loop through all responders in the_space
    for responder in the_space.responders:
        #send message via Webex Messaging to email address (if available)
        if responder.email!=None and responder.email!="":
            #need to skip the user of this application since it is not allowed
            #to send messages to oneself
            if responder.wbxpersonID!=modID and responder.wbxpersonID!=None:
                print(f'Sending Webex message to {responder.name}')
                api.messages.create(toPersonId=responder.wbxpersonID, text=msgSnd)
                print("Sent Webex message to: ",responder.email)

        #Only send out IMI or voice calls if IMI Service is configured
        if os.getenv('IMI_SERVICE_KEY')!="":
            #send message via SMS to mobile number (if available)
            if responder.sendSMS and responder.mobilenumber!=None and responder.mobilenumber!="":
                print(f'Sending SMS to {responder.name} at {responder.mobilenumber}')
                url = "https://api-sandbox.imiconnect.io/v1/sms/messages"
                payload = json.dumps({
                    "from": os.getenv('SMS_ORIGIN'),
                    "to": responder.mobilenumber,
                    "content": msgSnd,
                    "contentType": "TEXT"
                })
                headers = {
                    'Authorization': os.getenv('IMI_SERVICE_KEY'),
                    'Content-Type': 'application/json'
                }
                response = requests.request("POST", url, headers=headers, data=payload, verify=not DISABLE_SSL_VERIFY)
                print("Sent SMS: ",response.text)
                time.sleep(2)

            # call out to voice number and play message telling to check SMS or Webex messaging for call in info (if available)
            if responder.sendVoice and responder.voicenumber!=None and responder.voicenumber!="":
                print(f'Making voice call to {responder.name}')
                url = "https://api-sandbox.imiconnect.io/v1/voice/messages"
                payload = json.dumps({
                    "callerId": os.getenv('VOICE_ORIGIN'),
                    "dialedNumber": responder.voicenumber,
                    "audio": {
                        "type": "TTS",
                        "text": f'Hello, this is the incident responder. Please join meeting {rmMtgInfo.meetingNumber} by calling {rmMtgInfo.callInTollNumber}',
                        "textFormat": "TEXT",
                        "voice": "AriaNeural",
                        "engine": "AZURE",
                        "language": "en-US",
                        "gender": "female"
                    }
                })
                headers = {
                    'Authorization': os.getenv('IMI_SERVICE_KEY'),
                    'Content-Type': 'application/json'
                }
                response = requests.request("POST", url, headers=headers, data=payload, verify=not DISABLE_SSL_VERIFY)
                print("Made voice call: ",response.text)
                time.sleep(2)
    # redirect to link to launch the meeting
    return redirect(rmMtgInfo.meetingLink)

@app.route("/end_conference", methods=['GET', 'POST'])
def end_conference():
    global api

    # retrieve token from session
    teams_token = session['oauth_token']

    # retrieve roomID we are working with
    roomID = session['roomID']

    api = WebexTeamsAPI(access_token=teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)


    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()

    #clear out the incident name
    the_space.incidentname = ""

    #retrieve the Webex Person ID of the owner of this session, which should be a moderator in the space
    modID=session['modID']

    print("the_space responders: ",the_space.responders)
    responders_to_remove=[]
    for responder_to_del in the_space.responders:
        print(f'Evaluating for removal of space responder  {responder_to_del.name} with webex ID {responder_to_del.wbxpersonID}')

        #remove from the_space each responder and then remove them from actual Webex room

        #remove responder from the_space if they are not the moderator
        if responder_to_del.wbxpersonID!=modID:
            #the_space.responders.remove(responder_to_del)
            #mark responder for removal
            responders_to_remove.append(responder_to_del)
            print(f'Added responder id {responder_to_del.responders_id} to list to be removed')
            # now we remove the member from the Webex space if they
            # actually have a webex personID (not just external)
            if responder_to_del.wbxpersonID != None:
                # retrieve membership to delete
                theMemberships = api.memberships.list(roomId=roomID, personId=responder_to_del.wbxpersonID)
                for theMembership in theMemberships:
                    api.memberships.delete(theMembership.id)
                    print(f'Deleting user {responder_to_del.wbxpersonID} from space {roomID}')
        else:
            print(f'Skipping due to {responder_to_del.name} being moderator....')

    for to_remove in responders_to_remove:
        the_space.responders.remove(to_remove)
        print(f'Disassociated member {to_remove.responders_id} from the space in DB')

    db.session.commit()
    return space_selected(operation='EndConference')


@app.route('/AddExternal')
def AddExternal():
    print('In AddExernal')
    external_id = request.args.get('ext_id', '')
    print('External ID: ',external_id)

    #add to the_space the responder with ID external_id
    # retrieve roomID we are working with
    roomID = session['roomID']
    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()
    the_ext_responder= Responders.query.filter_by(responders_id=external_id).first()

    if the_ext_responder not in the_space.responders:
        the_space.responders.append(the_ext_responder)
    else:
        print(f'{the_ext_responder.name} is already associated to the space')
    db.session.commit()
    #alert_data = {'add_result':'added'}
    #return jsonify(result=alert_data)
    return space_selected(operation='AddExternal')


@app.route('/DelMember')
def DelMember():
    print('In DelMember')
    global api

    # retrieve token from session
    teams_token = session['oauth_token']
    roomID = session['roomID']
    #retrieve the Webex Person ID of the owner of this session, which should be a moderator in the space
    modID=session['modID']
    api = WebexTeamsAPI(access_token=teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)

    member_id = request.args.get('mem_id', '')
    print('Member ID to delete: ',member_id)

    #remove from the_space the responder with ID member_id and then remove from actual Webex room
    # retrieve roomID we are working with

    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()
    the_responder_delete= Responders.query.filter_by(responders_id=member_id).first()

    #remove resonder from the_space if they are not the moderator
    if the_responder_delete.wbxpersonID!=modID:
        the_space.responders.remove(the_responder_delete)
        print(f'Disassociated member {member_id} from the space in DB')

    db.session.commit()

    #now we remove the member from the Webex space if they
    #actually have a webex personID (not just external) and are not this rooms moderator
    if (the_responder_delete.wbxpersonID!=None and the_responder_delete.wbxpersonID!=modID):
        # retrieve membership to delete
        theMemberships = api.memberships.list(roomId=roomID,personId=the_responder_delete.wbxpersonID)
        for theMembership in theMemberships:
            api.memberships.delete(theMembership.id)
        print("Deleted member from roomID: ",roomID)

    #alert_data = {'del_result':'deleted'}
    #return jsonify(result=alert_data)

    return space_selected(operation='DelMember')



@app.route('/AddMember')
def AddMember():
    print('In AddMember')
    global api

    # retrieve token from session
    teams_token = session['oauth_token']
    roomID = session['roomID']

    api = WebexTeamsAPI(access_token=teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)

    member_id = request.args.get('mem_id', '')

    print('Member ID to add: ',member_id)

    #retrieve the proper the_space DB entry
    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()

    inSpace=False
    for a_responder in the_space.responders:
        if a_responder.wbxpersonID==member_id:
            inSpace=True

    if inSpace:
        print(f'Webex user personID {member_id} already in space.')
    else:
        #add to the actual webex room
        #TODO: consider if we want to provide the ability to add as a moderator
        api.memberships.create(roomId=roomID,personId=member_id)
        print(f'Added person ID {member_id} to the webex space')

        #then check to see if it exists in the 'responders' table, if not create a new one
        the_responder= Responders.query.filter_by(wbxpersonID=member_id).first()
        if the_responder==None:
            the_person=api.people.get(member_id)
            #pull mobile phone info from the person object to add to DB if available
            # and if user is in the same org of that person and has right to see phone numbers
            the_person_mobile=None
            the_person_voice=None
            sms_type=os.getenv('INT_PHONE_TYPE_SMS')
            voice_type=os.getenv('INT_PHONE_TYPE_VOICE')
            if the_person.phoneNumbers():
                for aNumber in the_person.phoneNumbers():
                    if aNumber['type'] == sms_type:  # i.e. "mobile":
                        the_person_mobile = aNumber['value']
                    if aNumber['type'] == voice_type:  # i.e. "work":
                        the_person_voice = aNumber['value']
            the_responder = Responders( name=the_person.displayName,
                                        wbxpersonID=member_id,
                                        email=the_person.emails[0],
                                        mobilenumber=the_person_mobile,
                                        voicenumber=the_person_voice,
                                        sendSMS=False,
                                        sendVoice=False)
            db.session.add(the_responder)
            print(f'Had to create responder {the_person.displayName} in responders table in DB...')

        # append the responder to the_space db entry
        the_space.responders.append(the_responder)
        print(f'Added member {member_id} to the space in DB')

    db.session.commit()
    return space_selected(operation='AddMember')

@app.route('/AddNewExternal')
def AddNewExternal():
    print('In AddNewExternal')

    ext_name = request.args.get('ext_name', None)
    ext_mobile = request.args.get('ext_mobile', None)
    ext_email = request.args.get('ext_email', None)
    ext_voice = request.args.get('ext_voice', None)

    if ext_name=="":
        ext_name=None
    if ext_mobile=="":
        ext_mobile=None
    if ext_email=="":
        ext_email=None
    if ext_voice=="":
        ext_voice=None

    print(f'New External to create: {ext_name},{ext_mobile},{ext_email},{ext_voice}')

    if (ext_name!=None and (ext_mobile!=None or ext_voice!=None)):
        the_responder = Responders( name=ext_name,
                                    mobilenumber=ext_mobile,
                                    email=ext_email,
                                    voicenumber=ext_voice,
                                    sendSMS=True if ext_mobile!=None else False ,
                                    sendVoice=True if ext_voice!=None else False)
        db.session.add(the_responder)
        print(f'Created external responder {ext_name} in responders table in DB...')
        db.session.commit()
    else:
        print("Not created: new external entry must have at least name and mobile or voice number.")
    return space_selected(operation='AddNewExternal')


@app.route('/UpdateInternalsList')
def UpdateInternalsList():
    print('In UpdateInternalsList')
    # Here we just re-draw screen but specify a subset of users to retrieve from
    # global directory
    search_str = request.args.get('search_str', '')
    return space_selected(operation='search:'+search_str)

@app.route('/UpdateIncName')
def UpdateIncName():
    print('In UpdateIncName')
    global api

    # retrieve token from session
    teams_token = session['oauth_token']
    roomID = session['roomID']
    incident_name=request.args.get('inc_name', '')

    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()
    # in case they changed the incident name since we will refresh the
    # whole form after this operation
    the_space.incidentname=incident_name
    db.session.commit()

    alert_data = {'update_inc_name_result':'updated'}
    return jsonify(result=alert_data)

@app.route('/toggleSendSMS')
def toggleSendSMS():
    print('In toggleSendSMS')
    toggleResult="Unchanged"

    member_id = request.args.get('mem_id', '')
    print('Member ID to toggle sendSMS flag: ',member_id)

    #Toggle the sendSMS flag
    the_responder_SMS_toggle= Responders.query.filter_by(responders_id=member_id).first()
    if the_responder_SMS_toggle.mobilenumber!=None and the_responder_SMS_toggle.mobilenumber!="":
        the_responder_SMS_toggle.sendSMS= not the_responder_SMS_toggle.sendSMS
        toggleResult='Enabled' if the_responder_SMS_toggle.sendSMS else 'Disabled'
        print(f'Toggled sendSMS for member {member_id}')
        db.session.commit()

    alert_data = {'toggle_result':toggleResult}
    return jsonify(result=alert_data)

@app.route('/toggleSendVoice')
def toggleSendVoice():
    print('In toggleSendVoice')
    toggleResult="Unchanged"

    member_id = request.args.get('mem_id', '')
    print('Member ID to toggle sendVoice flag: ',member_id)

    #Toggle the sendVoice flag
    the_responder_Voice_toggle= Responders.query.filter_by(responders_id=member_id).first()
    if the_responder_Voice_toggle.voicenumber!=None and the_responder_Voice_toggle.voicenumber!="":
        the_responder_Voice_toggle.sendVoice= not the_responder_Voice_toggle.sendVoice
        toggleResult='Enabled' if the_responder_Voice_toggle.sendVoice else 'Disabled'
        print(f'Toggled sendSMS for member {member_id}')
        db.session.commit()

    alert_data = {'toggle_result':toggleResult}
    return jsonify(result=alert_data)

@app.route('/sendOneInvite')
def sendOneInvite():
    print('In sendOneInvite')
    sendResult="NoneSent"

    global api

    # retrieve token from session
    teams_token = session['oauth_token']

    # retrieve roomID we are working with
    roomID = session['roomID']

    #retrieve the Webex Person ID of the owner of this session, which should be a moderator in the space
    modID=session['modID']


    api = WebexTeamsAPI(access_token=teams_token['access_token'], disable_ssl_verify=DISABLE_SSL_VERIFY)

    # obtain incident name from arguments
    formIncidentName = request.args.get('inc_name', '')

    print("Incident name from form: ",formIncidentName)

    the_space = Spaces.query.filter_by(wbxspaceID=roomID).first()

    if the_space != None:
        if formIncidentName!=the_space.incidentname:
            the_space.incidentname=formIncidentName
            db.session.commit()

    theIncidentName=the_space.incidentname

    theWebexSpace=api.rooms.get(roomID)

    #obtain the meeting information for the room.
    rmMtgInfo=api.rooms.get_meeting_info(roomID)

    #assemble message
    msgSnd=f'Join incident “{theIncidentName}” being handled in response room {theWebexSpace.title}.\
    Options (just use one):\n\
    Via Webex App: {rmMtgInfo.meetingLink}\n\
    Dial into the meeting: {rmMtgInfo.callInTollNumber}pp{rmMtgInfo.meetingNumber}# (press # again when prompted)'



    member_id = request.args.get('mem_id', '')
    print('Member ID to send one invite: ',member_id)

    #Send out one invite
    responder= Responders.query.filter_by(responders_id=member_id).first()

    # send message via Webex Messaging to email address (if available)
    if responder.email != None and responder.email != "":
        # need to skip the user of this application since it is not allowed
        # to send messages to oneself
        if responder.wbxpersonID != modID and responder.wbxpersonID != None:
            print(f'Sending Webex message to {responder.name}')
            api.messages.create(toPersonId=responder.wbxpersonID, text=msgSnd)
            print("Sent Webex message to: ", responder.email)
            sendResult += "WbxMsgSent"

    if os.getenv('IMI_SERVICE_KEY') != "":

        if responder.sendSMS:
        # Only send out IMI or voice calls if IMI Service is configured
            # send message via SMS to mobile number (if available)
            if responder.mobilenumber != None and responder.mobilenumber != "":
                print(f'Sending SMS to {responder.name} at {responder.mobilenumber}')
                url = "https://api-sandbox.imiconnect.io/v1/sms/messages"
                payload = json.dumps({
                    "from": os.getenv('SMS_ORIGIN'),
                    "to": responder.mobilenumber,
                    "content": msgSnd,
                    "contentType": "TEXT"
                })
                headers = {
                    'Authorization': os.getenv('IMI_SERVICE_KEY'),
                    'Content-Type': 'application/json'
                }
                response = requests.request("POST", url, headers=headers, data=payload, verify=not DISABLE_SSL_VERIFY)
                #TODO: Check response to see if really sent it
                print("Sent SMS: ", response.text)
                time.sleep(2)
                sendResult+="SMSSent"

        if responder.sendVoice:
            print("Making voice call....")
            # call out to voice number and play message telling to check SMS or Webex messaging for call in info (if available)
            if responder.voicenumber!=None and responder.voicenumber!="":
                print(f'Making voice call to {responder.name}')
                url = "https://api-sandbox.imiconnect.io/v1/voice/messages"
                payload = json.dumps({
                    "callerId": os.getenv('VOICE_ORIGIN'),
                    "dialedNumber": responder.voicenumber,
                    "audio": {
                        "type": "TTS",
                        "text": f'Hello, this is the incident responder. Please join meeting {rmMtgInfo.meetingNumber} by calling {rmMtgInfo.callInTollNumber}',
                        "textFormat": "TEXT",
                        "voice": "AriaNeural",
                        "engine": "AZURE",
                        "language": "en-US",
                        "gender": "female"
                    }
                })
                headers = {
                    'Authorization': os.getenv('IMI_SERVICE_KEY'),
                    'Content-Type': 'application/json'
                }
                response = requests.request("POST", url, headers=headers, data=payload, verify=not DISABLE_SSL_VERIFY)
                #TODO: check response to see if really made call to modify sendResult accordingly
                print("Made voice call: ",response.text)
                sendResult += "VoiceSent"

    alert_data = {'send_invite_result':sendResult}
    return jsonify(result=alert_data)

# Start the Flask web server
if __name__ == '__main__':

    print("Using PUBLIC_URL: ",PUBLIC_URL)
    print("Using redirect URI: ",REDIRECT_URI)
    app.run(host='0.0.0.0', port=5500, debug=True)


