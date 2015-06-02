"""Class: TimelimitHelper
"""

from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements

import interface
import plugins

class TimelimitHelper(BasePlugin):
    """Multi-plugin

    """

    meta_type = 'timelimit Helper'
    security = ClassSecurityInfo()

    def __init__( self, id=None, title=None , dunno=None):
        import pdb; pdb.set_trace()
        self._setId( id )
        self.title = title

    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):
        import pdb; pdb.set_trace()

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        import pdb; pdb.set_trace()


classImplements(TimelimitHelper, interface.ITimelimitHelper)

InitializeClass( TimelimitHelper )
