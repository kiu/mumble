# encoding: utf-8

# from __future__ import unicode_literals

import sys
import time
import tempfile
import Ice
import IcePy
from threading import Timer
from web.core import config
from marrow.util.convert import number, array
from marrow.util.bunch import Bunch
from collections import defaultdict
from datetime import datetime, timedelta
from brave.mumble.auth.model import Ticket
import re

Ice.loadSlice('-I/usr/share/Ice-3.5.1/slice Murmur.ice')
#Ice.loadSlice(b'', [b'-I' + (Ice.getSliceDir() or b'/usr/local/share/Ice-3.5/slice/'), b'Murmur.ice'])
import Murmur


log = __import__('logging').getLogger(__name__)
icelog = __import__('logging').getLogger('ice')


# NOTE: AUTH_FAIL is required for users to get prompted to reenter their password.
AUTH_FAIL = (-1, None, None)
UNKNOWN_USER_FAIL = (-2, None, None)
NO_INFO = (False, {})

# blue access tag list
access_blue_list = ('admin', 'member', 'blue')

# ---------------------------------------------------------

class IdlerGroup(object):
    __slots__ = ('time', 'target', 'channels')

    def __init__(self, time, target, channels=None):
        self.time = number(time)
        self.target = number(target)
        self.channels = array(channels) if channels else []


class IdlerHandler(object):
    def __init__(self):
        from web.core import config

        self.channel = number(config.get('idle.channel', 64))
        self.idlers = array(config.get('idle.groups', 'basic'))
        self.config = Bunch({i: IdlerGroup(
                time = config.get('idle.' + i + '.time', 3600),  # default: 1 hour
                target = config.get('idle.' + i + '.channel', self.channel),  # default: 64
                channels = config.get('idle.' + i + '.channels', ''),  # default: all
            ) for i in self.idlers})

        self.map = defaultdict()
        self.exclude = list(set((i.target for i in self.config.itervalues())))

        for config in self.config.itervalues():
            if config.channels:
                self.map.update({chan: config for chan in config.channels})
            else:
                self.map.default_factory = lambda: config

    def __call__(self, server):
        users = server.getUsers()
        exclude = self.exclude
        map = self.map

        for user in users:

            if isinstance(user, int):
                # log.info("Apparently users are integers. That's cool I guess. {0}".format(user))
                continue

            if user.channel in exclude: continue

            try:
                config = map[user.channel]
            except KeyError:
                continue

            if user.idlesecs > config.time:
                state = server.getState(user.session)
                if state:
                    state.channel = config.channel
                    server.setState(state)


class MumbleAuthenticator(Murmur.ServerUpdatingAuthenticator):
    """MongoDB-backed Mumble authentication agent.

    Murmur ICE reference: http://mumble.sourceforge.net/slice/Murmur.html
    """

    # TODO: Factor out all the "registered__exists=True, registered__not=None" clones.

    # ServerAuthenticator

    def authenticate(self, name, pw, certificates, certhash, certstrong, current=None):
        """Authenticate a Mumble user.

        * certificates: the X509 certificate chain of the user's certificate

        Returns a 3-tuple of user_id, user_name, groups.
        """
        try:

            log.info('authenticate "%s" %s', name, certhash)

            # if people try to login with SuperUser, immediately fail them
            if name == 'SuperUser':
                log.warn('Forced fall through for SuperUser')
                return UNKNOWN_USER_FAIL

            # Mark special users
            rankHide = False

            if '-norank' in name:
                name = name[:-7]
                rankHide = True

            # check if we should change the persons name
            spy = False
            if '-afs08spy' in name[-9:]:
                name = name[:-9]
                spy = True

            # Look up the user.
            try:
                user = Ticket.objects(character__name=name).only('tags', 'updated', 'password', 'corporation__id', 'corporation__ticker',
                                           'alliance__id', 'alliance__ticker', 'character__id', 'token').first()
            except Ticket.DoesNotExist:
                log.warn('Authentication Error: User "%s" not found in the Ticket database.', name)
                return UNKNOWN_USER_FAIL

            if not isinstance(pw, basestring):
                log.warn('Authentication Error: Provided password was not a string for user "%s"', name)
                return AUTH_FAIL
            elif pw == '':
                log.warn('Authentication Error: User "%s" did not provide a password for authentication.', name)
                return AUTH_FAIL
            elif user.password == '':
                log.warn('Authentication Error: No password set for user "%s"', name)
                return UNKNOWN_USER_FAIL
            elif not Ticket.password.check(user.password, pw):
                log.warn('Authentication Error: Incorrect password for user "%s"', name)
                return AUTH_FAIL

            # check to see if we need to update the users ticket info from core
            try:
                # If the token is not valid, deny access
                if not Ticket.authenticate(user.token, force_update=False):
                    return AUTH_FAIL
            except Exception as e:
                log.warning("Exception occured when attempting to authenticate user {0} {1}.".format(name, e))
                return AUTH_FAIL

            user = Ticket.objects(character__name=name).only('tags', 'updated', 'password', 'corporation__id', 'corporation__ticker',
                                           'alliance__id', 'alliance__ticker', 'character__id', 'token').first()

            # Define the registration date if one has not been set.
            Ticket.objects(character__name=name, registered=None).update(set__registered=datetime.utcnow())


            # Prepare tags
            tags = [i.replace('mumble.', '') for i in user.tags]
            tags.append('corporation-{0}'.format(user.corporation.id))
            if user.alliance and user.alliance.id:
                tags.append('alliance-{0}'.format(user.alliance.id))
            log.info('Found tags for "%s": %s', name, ', '.join(tags))

            # Only allow access for members
            for tag in access_blue_list:
                if tag in user.tags: break
            else:
                log.warn('User "%s" does not have permission to connect to this server.', name)
                return AUTH_FAIL

            # Set ticker
            ticker = user.alliance.ticker if user.alliance.ticker else '----'

            # Lets figure out the rank
            rank = []

            # Example to rewrite a name
            #if name == 'kiu Nakamura':
            #    name = 'kiu \'SuperNerd\' Nakamura'

            # Example to disguise a name and hide any ranks
            #if name == 'Obvious Spy':
            #    name = 'Joe Sixpack'
            #    rankHide = True

            # Example to append tags based on character name
            #if name == 'Mister FC':
            #    rank.append('FC')

            # Example to append based on group membership
            #if 'alliance.mil.fc' in tags:
            #    rank.append('FC')

            # Example to replace tags
            #if name == 'Great Leader':
            #    rank[:] = ['CEO']

            rankDesc = ', '.join(rank)

            if spy:
                spy_names = ['Penny', 'Sheldon', 'Lennard']
                spy_name = spy_names[randint(0, len(spy_names)-1)]
                spy_ticker = 'BRAVE'
                log.info('Requesting to disguise spy user "[{0}] {1}" as "[{2}] {3}"'.format(ticker, name, spy_ticker, spy_name))
                return (user.character.id, '[{0}] {1}'.format(spy_ticker, spy_name), tags)

            if rankHide:
                log.info('Requesting to hide ranks "({0})" of user "[{1}] {2}"'.format(rankDesc, ticker, name))
                return (user.character.id, '[{0}] {1}'.format(ticker, name), tags)

            if rank:
                log.info('Attaching rank "({0})" to user "[{1}] {2}"'.format(rankDesc, ticker, name))
                return (user.character.id, '[{0}] {1} ({2})'.format(ticker, name, rankDesc), tags)

            log.info('No ranks to attach for user "[{0}] {1}"'.format(ticker, name))
            return (user.character.id, '[{0}] {1}'.format(ticker, name), tags)

        except Exception as exc:
            log.critical("Exception occurred in authenticate! {0}".format(exc))
            return AUTH_FAIL

    def getInfo(self, id, current=None):
        return False, {}  # for now, let's pass through

        log.debug('getInfo %d', id)

        try:
            seen, name, ticker, comment = Ticket.objects(character__id=id).scalar('seen', 'character__name', 'alliance__ticker', 'comment').first()
        except TypeError:
            return NO_INFO

        if name is None: return NO_INFO
        if not ticker: ticker = '----'

        return True, {
            # Murmur.UserInfo.UserLastActive: seen,  # TODO: Verify the format this needs to be in.
            Murmur.UserInfo.UserName: '[{0}] {1}'.format(ticker, name),
            Murmur.UserInfo.UserComment: comment,
        }

    def nameToId(self, name, current=None):
        ticker, _, name = name.partition('] ')
        return Ticket.objects(character__name=name).scalar('character__id').first() or -2

    def idToName(self, id, current=None):
        user = Ticket.objects(character__id=id).only('character__name', 'alliance__ticker').first()
        if not user: return ''

        ticker = user.alliance.ticker or '----'

        return '[{0}] {1}'.format(user.character.name, user.alliance.ticker)

    def idToTexture(self, id, current=None):
        log.debug("idToTexture %d", id)
        return ''  # TODO: Pull the character's image from CCP's image server.  requests.get, CACHE IT

    # ServerUpdatingAuthenticator

    """

    def setInfo(self, id, info, current=None):
        return -1  # for now, let's pass through

        # We only allow comment updates.  Everything else is immutable.
        if Murmur.UserInfo.UserComment not in info or len(info) > 1:
            return 0

        updated = Ticket.objects(character__id=id).update(set__comment=info[Murmur.UserInfo.UserComment])
        if not updated: return 0
        return 1

    def setTexture(self, id, texture, current=None):
        return -1  # we currently don't handle these

    def registerUser(self, info, current=None):
        log.debug('registerUser "%s"', name)
        return 0

    def unregisterUser(self, id, current=None):
        log.debug("unregisterUser %d", id)
        return 0

    # TODO: Do we need this?  Seems only defined on Server, not our class.
    # def getRegistration(self, id, current=None):
    #     return (-2, None, None)

    def getRegisteredUsers(self, filter, current=None):
        results = Ticket.objects.scalar('character__id', 'character__name')
        if filter.strip(): results.filter(character__name__icontains=filter)
        return dict(results)

    """

def checkSecret(fn):
    def inner(self, *args, **kw):
        if not self.app.__secret:
            return fn(self, *args, **kw)

        current = kw.get('current', args[-1])

        if not current or current.ctx.get('secret', None) != self.app.__secret:
            log.error("Server transmitted invalid secret.")
            raise Murmur.InvalidSecretException()

        return fn(self, *args, **kw)

    return inner


def errorRecovery(value=None, exceptions=(Ice.Exception, )):
    def decorator(fn):
        def inner(*args, **kw):
            try:
                return fn(*args, **kw)
            except exceptions:
                raise
            except:
                log.exception("Unhandled error.")
                return value

        return inner

    return decorator


class MumbleMetaCallback(Murmur.MetaCallback):
    def __init__(self, app):
        Murmur.MetaCallback.__init__(self)
        self.app = app

    @errorRecovery()
    @checkSecret
    def started(self, server, current=None):
        """Attach an authenticator to any newly started virtual servers."""
        log.debug("Attaching authenticator to virtual server %d running Mumble %s.", server.id(), '.'.join(str(i) for i in self.app.meta.getVersion()[:3]))

        try:
            server.setAuthenticator(self.app.auth)
        except (Murmur.InvalidSecretException, Ice.UnknownUserException) as e:
            if getattr(e, 'unknown', None) != 'Murmur::InvalidSecretException':
                raise

            log.error("Invalid Ice secret.")
            return

    @errorRecovery()
    @checkSecret
    def stopped(self, server, current=None):
        if not self.app.connected:
            return

        try:
            log.info("Virtual server %d has stopped.", server.id())
        except Ice.ConnectionRefusedException:
            self.app.connected = False


class MumbleAuthenticatorApp(Ice.Application):
    def __init__(self, host='127.0.0.1', port=6502, secret=None, *args, **kw):
        super(MumbleAuthenticatorApp, self).__init__(*args, **kw)

        self.__host = host
        self.__port = port
        self.__secret = secret

        self.watchdog = None
        self.connected = False
        self.meta = None
        self.metacb = None
        self.auth = None
        self.exceptions = 0

        self.clean_idlers = IdlerHandler()

    def run(self, args):
        self.shutdownOnInterrupt()

        if not self.initializeIceConnection():
            return 1

        # Trigger the watchdog.
        self.failedWatch = True
        self.checkConnection()

        self.communicator().waitForShutdown()
        if self.watchdog: self.watchdog.cancel()

        if self.interrupted():
            log.warning("Caught interrupt; shutting down.")

        return 0

    def initializeIceConnection(self):
        ice = self.communicator()

        if self.__secret:
            ice.getImplicitContext().put("secret", self.__secret)
        else:
            log.warning("No secret defined; consider adding one.")

        log.info("Connecting to Ice server: %s:%d", self.__host, self.__port)

        base = ice.stringToProxy('Meta:tcp -h {0} -p {1}'.format(self.__host, self.__port))
        self.meta = Murmur.MetaPrx.uncheckedCast(base)

        adapter = ice.createObjectAdapterWithEndpoints('Callback.Client', 'tcp -h {0}'.format(self.__host))
        adapter.activate()

        metacbprx = adapter.addWithUUID(MumbleMetaCallback(self))
        self.metacb = Murmur.MetaCallbackPrx.uncheckedCast(metacbprx)

        authprx = adapter.addWithUUID(MumbleAuthenticator())
        self.auth = Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast(authprx)

        return self.attachCallbacks()

    def attachCallbacks(self, quiet=False):
        try:
            log.info("Attaching to live servers.")

            self.meta.addCallback(self.metacb)

            for server in self.meta.getBootedServers():
                log.debug("Attaching authenticator to virtual server %d running Mumble %s.", server.id(), '.'.join(str(i) for i in self.meta.getVersion()[:3]))
                server.setAuthenticator(self.auth)

                self.clean_idlers(server)

        except Ice.ConnectionRefusedException:
            log.error("Server refused connection.")
            self.connected = False
            return False

        except (Murmur.InvalidSecretException, Ice.UnknownUserException) as e:
            self.connected = False

            if isinstance(e, Ice.UnknownUserException) and e.unknown != 'Murmur:InvalidSecretException':
                raise  # we can't handle this error

            log.exception("Invalid Ice secret.")
            return False

        self.connected = True
        return True

    def checkConnection(self):
        try:
            self.failedWatch = not self.attachCallbacks()

        except Ice.Exception as e:
            log.exception("Failed connection check.")
        except Exception as ex:
            log.critical("EXCEPTION OCCURRED IN CHECKCONNECTION {0}".format(ex))
        try:
            self.watchdog = Timer(30, self.checkConnection)  # TODO: Make this configurable.
            self.watchdog.start()
            self.exceptions = 0
        except Exception as exc:
            log.critical("ERROR OCCURRED IN LOWER CHECKCONN {0}".format(exc))
            if self.exceptions < 50:
                self.checkConnection()
                self.exceptions = self.exceptions + 1


class CustomLogger(Ice.Logger):
    def _print(self, message):
        icelog.info(message)

    def trace(self, category, message):
        icelog.debug("trace %s\n%s", category, message)

    def warning(self, message):
        icelog.warning(message)

    def error(self, message):
        icelog.error(message)



def main():
    """

    PYTHONPATH=/usr/local/lib/python2.7/site-packages paster shell
    from brave.mumble.service import main; main()

    """
    secret = config.get('mumble.ice.secret')

    log.info("Ice initializing.")

    try:
        prop = Ice.createProperties([])
        prop.setProperty("Ice.ImplicitContext", "Shared")
        prop.setProperty("Ice.MessageSizeMax", "65535")
        prop.setProperty("Ice.Default.EncodingVersion", "1.0")

        idd = Ice.InitializationData()
        idd.logger = CustomLogger()
        idd.properties = prop

        app = MumbleAuthenticatorApp(secret=secret)
        app.main(['brave-mumble'], initData=idd)

        log.info("Shutdown complete.")
    except Exception as e:
        log.critical("EXCEPTION CAUGHT IN MAIN {0}".format(e))

