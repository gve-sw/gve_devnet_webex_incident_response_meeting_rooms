from flask import Flask, request, redirect, session, url_for, render_template, make_response
from flask_sqlalchemy import SQLAlchemy

from server import db
db.create_all()

from server import Responders,Spaces


the_responder1 = Responders(name='Milena Chaves', email='mchaves@cisco.com', mobilenumber='+50666799470')
the_responder2 = Responders(name='Gerardo Chaves', email='gchaves@cisco.com', mobilenumber='+50688799470')
the_responder3 = Responders(name='Erica Chaves', email='echaves@cisco.com', mobilenumber='+50622799470')
the_responder4 = Responders(name='Emma Chaves', email='emchaves@cisco.com', mobilenumber='+50688799411')

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
