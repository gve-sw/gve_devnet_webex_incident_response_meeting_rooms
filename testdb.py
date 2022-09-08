from flask import Flask, request, redirect, session, url_for, render_template, make_response
from flask_sqlalchemy import SQLAlchemy

from server import db

# will not create tables if already there
db.create_all()

from server import Responders,Spaces


the_responder1 = Responders(name='Peter Parker', email='pparker@acme.com', mobilenumber='+18185552563')
the_responder2 = Responders(name='John Stamos', email='jstamos@acme.com', mobilenumber='+18185552263')
the_responder3 = Responders(name='Erica Stone', email='estone@acme.com', mobilenumber='+18185552543')
the_responder4 = Responders(name='Emma Johansen', email='ejohansen@acme.com', mobilenumber='+18185559213')

the_space1 = Spaces(incidentname='FirstResponseSpace', wbxspaceID='afadsfwerw234234wersfasxxzcsd')
the_space2 = Spaces(incidentname='SecondResponseSpace', wbxspaceID='afadsfwerw234234wersfasxxzcsd')

the_space1.responders.append(the_responder1)
the_space1.responders.append(the_responder2)
the_space1.responders.append(the_responder3)

the_space2.responders.append(the_responder4)
the_space2.responders.append(the_responder1)

db.session.add(the_responder1)
db.session.add(the_responder2)
db.session.add(the_responder3)
db.session.add(the_responder4)
db.session.add(the_space1)
db.session.add(the_space2)

db.session.commit()

for a in Spaces.query.all():
    print(a.incidentname)
    print("Responders: ",end=" ")
    space_to_remove_member=a
    for b in a.responders:
        print(b.name,end=", ")
        responder_to_delete=b
    print("-----")

print("==== Now lets try to remove ====")

space_to_remove_member.responders.remove(responder_to_delete)
db.session.commit()

for a in Spaces.query.all():
    print(a.incidentname)
    print("Responders: ",end=" ")
    for b in a.responders:
        print(b.name,end=", ")
    print("-----")
