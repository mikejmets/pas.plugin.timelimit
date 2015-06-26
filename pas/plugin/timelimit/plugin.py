"""Class: TimelimitHelper
"""

import binascii
import interface
import logging
from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass
from App.config import getConfiguration
from bb.toaster.browser.timelimit.view import decrementVouchers
from DateTime import DateTime
from plone import api
from plone.session import tktauth
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

    timelimit = 60
    path = '/'
    cookie_name = '__ac'
    _properties = (
            {
                 "id": "timelimit",
                 "label": "Voucher validity timeout (in minutes)",
                 "type": "int",
                 "mode": "w",
             },
            {
                 "id": "path",
                 "label": "Cookie path",
                 "type": "string",
                 "mode": "w",
            },
            )

    def __init__( self, id=None, title=None , dunno=None):
        self._setId( id )
        self.title = title

    def _getUserInfo(self, credentials):
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
        return pas._verifyUser(pas.plugins, user_id=userid)

    # IAuthenticationPlugin implementation
    def authenticateCredentials(self, credentials):

        #import pdb; pdb.set_trace()
        info = self._getUserInfo(credentials)
        if info is None:
            return None
        user = api.user.get(userid=info['id'])

        login_time = user.getProperty('login_time', None)
        if login_time is None:
            logging.debug('TimeLimit: No login time')
            return None

        #This never fails, it has side effects on user voucher count
        minutes = (DateTime() - login_time) * 24 * 60 
        logging.debug("limit = %s; login_time = %s; diff = %s minutes" % (
                self.timelimit, login_time, minutes))
        if minutes > self.timelimit:
            logging.debug('Time %s minutes is up' % self.timelimit)
            vouchers = user.getProperty('vouchers')
            if vouchers > 0:
                decrementVouchers(info['id'])
        return None

    # IChallengePlugin implementation
    def challenge(self, request, response):
        #print 'Challenge'
        creds = self.extractCredentials(request)
        info = self._getUserInfo(creds)
        if info is None:
            return None
        user = api.user.get(userid=info['id'])

        if user is None:
            return None
        #Get user folder and find survey
        mt = api.portal.get_tool('portal_membership')
        home = mt.getHomeFolder(id=user.id)
        if not home:
            #print 'No home folder found'
            return None
        hassurvey = len(
            [v for v in home.values() if v.portal_type == 'bb.toaster.survey'])
        #If no Survey, direct to timeupnosurvey
        portal = api.portal.get()
        if not hassurvey:
            response.redirect(
                '%s/@@timeupnosurvey' % portal.absolute_url(), lock=1)
            return True
        else:
            #Else (was If Survey), direct to thank you view timeuphassurvey
            response.redirect(
                '%s/@@timeuphassurvey' % portal.absolute_url(), lock=1)
            return True

classImplements(
        TimelimitHelper,
        interface.ITimelimitHelper,
        plugins.IAuthenticationPlugin,
        plugins.IChallengePlugin,
        *implementedBy(SessionPlugin))

InitializeClass( TimelimitHelper )
