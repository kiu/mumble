# encoding: utf-8

from __future__ import unicode_literals

import re
from datetime import datetime, timedelta, tzinfo
from random import choice
from string import printable
from mongoengine import BinaryField
from mongoengine.base import BaseField
from scrypt import error as scrypt_error, encrypt as scrypt, decrypt as validate_scrypt

from web.core import config
from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, IntField, EmbeddedDocumentField, ListField
from braveapi.client import API


log = __import__('logging').getLogger(__name__)


# TODO Move to config file
# Time (in hours) after which a ticket needs to be rechecked
update_timeout=1

# Timezone Definitions
ZERO = timedelta(0)
class UTC(tzinfo):
    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

utc = UTC()

# --------------------------------------------------

class PasswordField(BinaryField):
    def __init__(self, difficulty=1, **kwargs):
        self.difficulty = difficulty
        
        super(PasswordField, self).__init__(**kwargs)
    
    def to_python(self, value):
        return value
    
    def __set__(self, instance, value):
        if instance._initialised:
            if isinstance(value, unicode):
                value = value.encode('utf-8')
            
            salt = b''.join([choice(printable) for i in range(32)])
            value = str(scrypt(salt, value, maxtime=self.difficulty))
        
        return super(PasswordField, self).__set__(instance, value)
    
    def to_mongo(self, value):
        if value is None:
            return value
        
        return super(PasswordField, self).to_mongo(value)
    
    def check(self, source, value):
        try:
            # It may be a tiny bit more difficult for us to validate than it was to generate.
            # Even a few ms too long will give us bad results.
            validate_scrypt(source, value, self.difficulty * 4)
            
        
        except scrypt_error:
            return False
        except Exception as e:
            log.warn(e)
            return False
        return True


# TODO: Deduplication?  Only store integer ID, turn Entity into its own collection.
# Would require migration map/reduce and scrubbing query.

class Entity(EmbeddedDocument):
    meta = dict(allow_inheritance=False)
    
    id = IntField(db_field='i')
    name = StringField(db_field='n')
    ticker = StringField(db_field='t')


class Ticket(Document):
    meta = dict(
            collection = 'Tickets',
            allow_inheritance = False,
            indexes = [
                    'character.id'
                ],
        )
    
    token = StringField(db_field='t')
    
    character = EmbeddedDocumentField(Entity, db_field='c', default=lambda: Entity())
    corporation = EmbeddedDocumentField(Entity, db_field='o', default=lambda: Entity())
    alliance = EmbeddedDocumentField(Entity, db_field='a', default=lambda: Entity())
    tags = ListField(StringField(), db_field='g', default=list)
    perms = ListField(StringField(), db_field='p', default=list)
    
    password = PasswordField(db_field='pw', difficulty=0.125)
    comment = StringField(db_field='m', default='')
    
    expires = DateTimeField(db_field='e')
    seen = DateTimeField(db_field='s')  # TODO: Update this when the user connects/disconnects.
    updated = DateTimeField(db_field='u')
    registered = DateTimeField(db_field='r')
    
    @property
    def has_password(self):
        return bool(self.password)
    
    def __repr__(self):
        return "<Ticket {0.id} \"{0.character.name}\">".format(self)
    
    @classmethod
    def authenticate(cls, identifier, password=None, force_update=True):


        # See if we can get the user object by the passed in token
        try:
            user = cls.objects(token=identifier).first()
        except Exception as e:
            force_update = True

        try:
            if force_update or (datetime.now(tz=utc) - user.updated > timedelta(hours=update_timeout)):

                before = datetime.now()

                api = API(config['api.endpoint'], config['api.identity'], config['api.private'], config['api.public'])
                result = api.core.info(identifier)

                after = datetime.now()
                log.info("Check Query to Core took {0}".format(after - before))

                #Invalid token sent. Probably a better way to handle this.
                if not result:
                    log.info("Token %s not valid, or connection to Core has been lost.", identifier)
                    return None

                user = cls.objects(character__id=result.character.id).first()

                if not user:
                    user = cls(token=identifier, expires=result.expires, seen=datetime.utcnow())
                elif identifier != user.token:
                    user.token = identifier

                user.character.id = result.character.id
                user.character.name = result.character.name
                user.corporation.id = result.corporation.id
                user.corporation.name = result.corporation.name

                corpshort = api.lookup.corporation(result.corporation.id, only='short')
                if corpshort and corpshort.success:
                        user.corporation.ticker = corpshort.short

                all = Ticket.objects(alliance__id=(result.alliance.id if result.alliance else 0)).first()

                if result.alliance and all:
                    user.alliance = all.alliance
                elif result.alliance:
                    user.alliance.id = result.alliance.id
                    user.alliance.name = result.alliance.name

                    alliance = api.lookup.alliance(result.alliance.id, only='short')
                    if alliance and alliance.success:
                        user.alliance.ticker = alliance.short
                else:
                    user.alliance = None

                filtered_perms = []
                for perm in result.perms:
                    if perm.startswith('mumble.'):
                        filtered_perms.append(perm)

                user.perms = filtered_perms
                user.tags = [i.replace('mumble.', '') for i in (result.tags if 'tags' in result else [])]
                user.updated = datetime.now()
                user.save()

                log.info("Updating user %s having %s and %s", user.character.name, user.tags, user.perms)

        except Exception as e:
            log.info("General Exception(%s): %s", identifier, e)
            return None

        return user.id, user
    
    @classmethod
    def lookup(cls, identifier):
        """Thaw current user data based on session-stored user ID."""
        
        user = cls.objects(id=identifier).first()
        
        if user:
            user.update(set__seen=datetime.utcnow())
        
        return user
