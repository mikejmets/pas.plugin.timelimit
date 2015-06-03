"""Class: TimelimitHelper
"""

import interface
import logging
from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass
from DateTime import DateTime
from plone import api
from plone.session.plugins.session import SessionPlugin
from Products.PluggableAuthService.interfaces import plugins
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from zope.interface import implementedBy

class TimelimitHelper(SessionPlugin):
    """Session plugin which times out after an hour and then never
       lets you back in
    """

    meta_type = 'Timelimit Helper'
    security = ClassSecurityInfo()
    _dont_swallow_my_exceptions = True

    def __init__( self, id=None, title=None , dunno=None):
        self._setId( id )
        self.title = title
        self.timelimit = 60.0 #minutes

    # IAuthenticationPlugin implementation
    def authenticateCredentials(self, credentials):
        if not credentials.get("source", None)=="plone.session":
            return None

        if not credentials.get("source", None)=="plone.session":
            return None

        ticket=credentials["cookie"]
        ticket_data = self._validateTicket(ticket)
        if ticket_data is None:
            return None
        (digest, userid, tokens, user_data, timestamp) = ticket_data
        pas=self._getPAS()
        info=pas._verifyUser(pas.plugins, user_id=userid)
        if info is None:
            return None

        user = api.user.get(userid=userid)
        vouchers = user.getProperty('vouchers')
        if not vouchers:
            logging.debug('No more vouchers')
            return None

        login_time = user.getProperty('login_time', None)
        if login_time is None:
            return None

        minutes = (DateTime() - login_time) * 24 * 60 
        print "limit = %s; login_time = %s; diff = %s minutes" % (
                self.timelimit, login_time, minutes)
        if minutes > self.timelimit:
            logging.debug('Time %s minutes is up' % self.timelimit)
            user.setMemberProperties({'vouchers': vouchers-1})
            return None
        return (info['id'], info['login'])

classImplements(
        TimelimitHelper,
        interface.ITimelimitHelper,
        plugins.IAuthenticationPlugin,
        *implementedBy(SessionPlugin))

InitializeClass( TimelimitHelper )
