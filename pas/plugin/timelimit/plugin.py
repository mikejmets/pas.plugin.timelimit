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
    trusted_referer = []
    trusted_login = ''
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
                 "id": "trusted_login",
                 "label": "Trusted Login Id",
                 "type": "string",
                 "mode": "w",
             },
            {
                 "id": "trusted_referer",
                 "label": "Trusted Referred Url",
                 "type": "lines",
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
        #print 'authenticateCredentials'
        if self.trusted_login and \
           self.trusted_login == credentials.get('user_id', ''):
            #print 'authenticateCredentials creds with %s' % self.trusted_login
            return (self.trusted_login, self.trusted_login)

        info = self._getUserInfo(credentials)
        if info is None:
            return None
        user = api.user.get(userid=info['id'])

        login_time = user.getProperty('login_time', None)
        if login_time is None:
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
        #print 'auth: %s %s' % (info['id'], info['login'])
        return (info['id'], info['id'])

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

    # IExtractionPlugin implementation
    def extractCredentials(self, request):
        """ Extraction Part """

        creds = {}
        referer = request.environ.get('HTTP_REFERER', 'zzzzzzzzzz')
        trusted = False
        if self.trusted_referer and \
           self.trusted_login:
            for url in self.trusted_referer:
                if referer.startswith(url):
                    trusted = True
                    break
        if trusted:
            #print 'extract creds with %s' % self.trusted_login
            creds.update({'user_id':self.trusted_login})
            cookie=self._getCookie(self.trusted_login, request.response)
        else:
            #print 'super extractCredentials'
            if not self.cookie_name in request:
                #print 'extractCredentials: cookie name not in request'
                return creds
            cookie=request.get(self.cookie_name)
        try:
            creds["cookie"]=binascii.a2b_base64(request.get(self.cookie_name))
        except binascii.Error:
            # If we have a cookie which is not properly base64 encoded it
            # can not be ours.
            #print 'extractCredentials: binascii'
            return creds
        creds["source"]="plone.session" # XXX should this be the id?

        #print 'extractCredentials: returns %s' % creds
        return creds

    def _getCookie(self, userid, response, tokens=(), user_data=''):
        cookie = tktauth.createTicket(
            secret=self._getSigningSecret(),
            userid=userid,
            tokens=tokens,
            user_data=user_data,
            mod_auth_tkt=False,
            )
        cookie=binascii.b2a_base64(cookie).rstrip()
        # disable secure cookie in development mode, to ease local testing
        if getConfiguration().debug_mode:
            secure = False
        else:
            secure = self.secure
        options = dict(path=self.path, secure=secure, http_only=True)
        options['expires'] = 0
        response.setCookie(self.cookie_name, cookie, **options)
        cookies = response.cookies
        return cookies[self.cookie_name]

classImplements(
        TimelimitHelper,
        interface.ITimelimitHelper,
        plugins.IAuthenticationPlugin,
        plugins.IChallengePlugin,
        plugins.IExtractionPlugin,
        plugins.ICredentialsUpdatePlugin,
        *implementedBy(SessionPlugin))

InitializeClass( TimelimitHelper )
