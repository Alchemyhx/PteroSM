# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask_script import Manager, Server
from main import app, db, data_query

manager = Manager(app)
manager.add_command("server",Server())

@manager.shell
def make_shell_context():
    return dict(app = app, db = db, data_query = data_query)
    
if __name__ == '__main__':
    manager.run()