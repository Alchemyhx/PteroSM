# !/usr/bin/env python3
# -*- coding: utf-8 -*-

class Config(object):
    CSRF_ENABLED = True
    SECRET_KEY = '736670cb10a600b695a55839ca3a5aa54a7d7356cdef815d2ad6e19a2031182b'
    
class ProdConfig(Config):
    pass
    
class DevConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///database.db"
    