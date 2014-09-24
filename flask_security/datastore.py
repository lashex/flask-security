# -*- coding: utf-8 -*-
"""
    flask.ext.security.datastore
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains an user datastore classes.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from .utils import get_identity_attributes, string_types


class Datastore(object):
    def __init__(self, db):
        self.db = db

    def commit(self):
        pass

    def put(self, model):
        raise NotImplementedError

    def delete(self, model):
        raise NotImplementedError


class SQLAlchemyDatastore(Datastore):
    def commit(self):
        self.db.session.commit()

    def put(self, model):
        self.db.session.add(model)
        return model

    def delete(self, model):
        self.db.session.delete(model)


class MongoEngineDatastore(Datastore):
    def put(self, model):
        model.save()
        return model

    def delete(self, model):
        model.delete()


class PeeweeDatastore(Datastore):
    def put(self, model):
        model.save()
        return model

    def delete(self, model):
        model.delete_instance()


class DynamoDatastore(Datastore):
    def put(self, model):
        model.save()
        return model

    def delete(self, model):
        model.delete()


class UserDatastore(object):
    """Abstracted user datastore.

    :param user_model: A user model class definition
    :param role_model: A role model class definition
    """

    def __init__(self, user_model, role_model):
        self.user_model = user_model
        self.role_model = role_model

    def _prepare_role_modify_args(self, user, role):
        if isinstance(user, string_types):
            user = self.find_user(email=user)
        if isinstance(role, string_types):
            role = self.find_role(role)
        return user, role

    def _prepare_create_user_args(self, **kwargs):
        kwargs.setdefault('active', True)
        roles = kwargs.get('roles', [])
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        kwargs['roles'] = roles
        return kwargs

    def get_user(self, id_or_email):
        """Returns a user matching the specified ID or email address"""
        raise NotImplementedError

    def find_user(self, *args, **kwargs):
        """Returns a user matching the provided parameters."""
        raise NotImplementedError

    def find_role(self, *args, **kwargs):
        """Returns a role matching the provided name."""
        raise NotImplementedError

    def add_role_to_user(self, user, role):
        """Adds a role tp a user

        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        if role not in user.roles:
            user.roles.append(role)
            self.put(user)
            return True
        return False

    def remove_role_from_user(self, user, role):
        """Removes a role from a user

        :param user: The user to manipulate
        :param role: The role to remove from the user
        """
        rv = False
        user, role = self._prepare_role_modify_args(user, role)
        if role in user.roles:
            rv = True
            user.roles.remove(role)
            self.put(user)
        return rv

    def toggle_active(self, user):
        """Toggles a user's active status. Always returns True."""
        user.active = not user.active
        return True

    def deactivate_user(self, user):
        """Deactivates a specified user. Returns `True` if a change was made.

        :param user: The user to deactivate
        """
        if user.active:
            user.active = False
            return True
        return False

    def activate_user(self, user):
        """Activates a specified user. Returns `True` if a change was made.

        :param user: The user to activate
        """
        if not user.active:
            user.active = True
            return True
        return False

    def create_role(self, **kwargs):
        """Creates and returns a new role from the given parameters."""

        role = self.role_model(**kwargs)
        return self.put(role)

    def find_or_create_role(self, name, **kwargs):
        """Returns a role matching the given name or creates it with any
        additionally provided parameters
        """
        kwargs["name"] = name
        return self.find_role(name) or self.create_role(**kwargs)

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters."""
        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(**kwargs)
        return self.put(user)

    def delete_user(self, user):
        """Delete the specified user

        :param user: The user to delete
        """
        self.delete(user)


class SQLAlchemyUserDatastore(SQLAlchemyDatastore, UserDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security that assumes the
    use of the Flask-SQLAlchemy extension.
    """
    def __init__(self, db, user_model, role_model):
        SQLAlchemyDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    def get_user(self, identifier):
        if self._is_numeric(identifier):
            return self.user_model.query.get(identifier)
        for attr in get_identity_attributes():
            query = getattr(self.user_model, attr).ilike(identifier)
            rv = self.user_model.query.filter(query).first()
            if rv is not None:
                return rv

    def _is_numeric(self, value):
        try:
            int(value)
        except ValueError:
            return False
        return True

    def find_user(self, **kwargs):
        return self.user_model.query.filter_by(**kwargs).first()

    def find_role(self, role):
        return self.role_model.query.filter_by(name=role).first()


class MongoEngineUserDatastore(MongoEngineDatastore, UserDatastore):
    """A MongoEngine datastore implementation for Flask-Security that assumes
    the use of the Flask-MongoEngine extension.
    """
    def __init__(self, db, user_model, role_model):
        MongoEngineDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    def get_user(self, identifier):
        from mongoengine import ValidationError
        try:
            return self.user_model.objects(id=identifier).first()
        except ValidationError:
            pass
        for attr in get_identity_attributes():
            query_key = '%s__iexact' % attr
            query = {query_key: identifier}
            rv = self.user_model.objects(**query).first()
            if rv is not None:
                return rv

    def find_user(self, **kwargs):
        try:
            from mongoengine.queryset import Q, QCombination
        except ImportError:
            from mongoengine.queryset.visitor import Q, QCombination
        from mongoengine.errors import ValidationError

        queries = map(lambda i: Q(**{i[0]: i[1]}), kwargs.items())
        query = QCombination(QCombination.AND, queries)
        try:
            return self.user_model.objects(query).first()
        except ValidationError:  # pragma: no cover
            return None

    def find_role(self, role):
        return self.role_model.objects(name=role).first()

    # TODO: Not sure why this was added but tests pass without it
    # def add_role_to_user(self, user, role):
    #     rv = super(MongoEngineUserDatastore, self).add_role_to_user(user, role)
    #     if rv:
    #         self.put(user)
    #     return rv


class PeeweeUserDatastore(PeeweeDatastore, UserDatastore):
    """A PeeweeD datastore implementation for Flask-Security that assumes
    the use of the Flask-Peewee extension.

    :param user_model: A user model class definition
    :param role_model: A role model class definition
    :param role_link: A model implementing the many-to-many user-role relation
    """
    def __init__(self, db, user_model, role_model, role_link):
        PeeweeDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)
        self.UserRole = role_link

    def get_user(self, identifier):
        try:
            return self.user_model.get(self.user_model.id == identifier)
        except ValueError:
            pass

        for attr in get_identity_attributes():
            column = getattr(self.user_model, attr)
            try:
                return self.user_model.get(column ** identifier)
            except self.user_model.DoesNotExist:
                pass

    def find_user(self, **kwargs):
        try:
            return self.user_model.filter(**kwargs).get()
        except self.user_model.DoesNotExist:
            return None

    def find_role(self, role):
        try:
            return self.role_model.filter(name=role).get()
        except self.role_model.DoesNotExist:
            return None

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters."""
        roles = kwargs.pop('roles', [])
        user = self.user_model(**self._prepare_create_user_args(**kwargs))
        user = self.put(user)
        for role in roles:
            self.add_role_to_user(user, role)
        self.put(user)
        return user

    def add_role_to_user(self, user, role):
        """Adds a role tp a user

        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        result = self.UserRole.select() \
            .where(self.UserRole.user == user.id, self.UserRole.role == role.id)
        if result.count():
            return False
        else:
            self.put(self.UserRole.create(user=user.id, role=role.id))
            return True

    def remove_role_from_user(self, user, role):
        """Removes a role from a user

        :param user: The user to manipulate
        :param role: The role to remove from the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        result = self.UserRole.select() \
            .where(self.UserRole.user == user, self.UserRole.role == role)
        if result.count():
            query = self.UserRole.delete().where(
                self.UserRole.user == user, self.UserRole.role == role)
            query.execute()
            return True
        else:
            return False


import uuid
import logging
import re
class DynamoUserDatastore(DynamoDatastore, UserDatastore):
    """ A DynamoDB datastore implementation for use by Flask-Security that
    assumes the use of the AWS Python (boto) SDK.
    """
    def __init__(self, db, user_model, role_model):
        """

        :param db: the DynamoDatastore to use
        :param user_model: A user model class definition
        :param role_model: A role model class definition
        :return:
        """
        DynamoDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)
        self.user_model = user_model
        self.role_model = role_model

    @staticmethod
    def _is_uuid(maybe_uuid):
        logging.debug('maybe_uuid: {0}'.format(maybe_uuid))
        try:
            uuid.UUID(maybe_uuid)
            return True
        except ValueError as ve:
            logging.debug(
                '_is_uuid given invalid value:{0} message:{1}'.format(maybe_uuid,
                                                                      ve))
        except TypeError as te:
            logging.debug(
                '_is_uuid given invalid type:{0} message:{1}'.format(maybe_uuid,
                                                                     te))
        return False

    @staticmethod
    def _is_email(maybe_email):
        # thanks to this answer on StackOverflow
        # http://stackoverflow.com/questions/8022530
        exp = r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$"
        return re.match(exp, maybe_email)

    def get_user(self, id_or_email_or_username):
        """Returns a user matching the specified ID, email address or username
        """
        returned = None
        if DynamoUserDatastore._is_uuid(id_or_email_or_username):
            returned = self.get_user_by_id(id_or_email_or_username)
        elif DynamoUserDatastore._is_email(id_or_email_or_username):
            returned = self.find_user(email=id_or_email_or_username)
        else:
            returned = self.find_user(username=id_or_email_or_username)
        return returned

    def find_user(self, **kwargs):
        """Finds and returns the first user matching the provided parameters.

        :param id: the identifier of the user to find. This is used post-login.
        :param email: the email address of the user to find.
        :param username: this is used if/when there is a username on user_model
        """
        logging.debug('find_user {0}'.format(kwargs))
        um = self.user_model(self.db)
        keys = list(kwargs.keys())
        results = []
        if 'id' in keys:
            uid = kwargs.get('id')
            return self.get_user_by_id(uid)

        if 'email' in keys:
            email = kwargs.get('email')
            logging.debug('find_user with email: {0}'.format(email))
            if hasattr(um, 'email_index') and um.email_index is not None:
                # TODO Index exists, so use it
                # kw = {
                #     '{0}{1}'.format(um.email_attribute, '__eq'): email,
                #     'index': um.email_index
                #     'limit': 1
                # }
                # log.debug('find_user scan parameters {0}'.format(kw))
                # results = um.user_table.query_2(**kw)
                pass
            else:
                logging.debug('find_user scanning for email: {0}'.format(email))
                # Just do a scan to find the email
                kw = {
                    '{0}{1}'.format(um.email_attribute, '__eq'): email,
                    'limit': 1
                }
                logging.debug('find_user scan parameters {0}'.format(kw))
                results = um.table.scan(**kw)

        if 'username' in keys:
            username = kwargs.get('username')
            logging.debug('find_user with username: {0}'.format(username))
            if hasattr(um, 'username_index') and um.username_index is not None:
                # TODO Index exists, so use it
                pass
            else:
                logging.debug('find_user scanning for username: {0}'.format(
                    username))
                kw = {
                    '{0}{1}'.format(um.username_field, '__eq'): username,
                    'limit': 1
                }
                logging.debug('find_user scan parameters {0}'.format(kw))
                results = self.user_model(self.db).table.scan(**kw)

        # TODO add in support for arbitrary arguments as query params

        for res in results:
            # will always return first result
            user = self.user_model(self.db, item=res)
            logging.debug('find_user result keys: {0}'.format(res.keys()))
            logging.debug('find_user returning user.id:{0}'.format(user.id))
            return user

        return None

    def create_role(self, **kwargs):
        """Creates and returns a new role from the given parameters."""
        raise NotImplementedError

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters.

        :param email: the email address of the user [required]
        :param password: the password of the user [required]
        """
        keys = list(kwargs.keys())
        if 'email' not in keys:
            raise ValueError('email value is required')

        email = kwargs.get('email')
        if not DynamoUserDatastore._is_email(email):
            raise ValueError('invalid email value:{0}'.format(email))

        if 'password' not in keys:
            raise ValueError('password is a required field')

        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(self.db, **kwargs)
        return self.put(user)

    def get_user_by_id(self, user_id):
        """Get a User by user ID.

        :param user_id: the user ID of the User to obtain
        :return: a user_model User
        """
        um = self.user_model(self.db)
        user = um.table.get_item(**{
            '{0}'.format(um.user_id_attribute): user_id,
        })
        logging.debug('get_user_by_id id: {0}'.format(user_id))
        return self.user_model(self.db, item=user)


from .core import RoleMixin
class DynamoRole(RoleMixin):
    def __init__(self, name, description=''):
        # self.id = role_id
        self.name = name
        self.description = description

    def __str__(self):
        return "<Role name: '{0}'>".format(self.name)


from .core import UserMixin
from boto.dynamodb2.table import Table, Item
class DynamoUser(UserMixin):
    """
    Dynamo User abstract class.

    Subclasses must have the following required class variables configured.
    :var user_id_attribute: the name of the user_id attribute [required]
    :var email_attribute: the name of the email attribute [required]
    :var active_attribute: the name of the active attribute [required]
    :var password_attribute: the name of the password attribute [required]
    :var roles_attribute: the name of the roles attribute [required]
    :var table_name: the name of the DynamoDB table to use for Users [required]
    :var username_attribute: the name of the username attribute [optional]
    :var email_index: name of the email index to use or 'None' [optional]
    :var username_index: name of the username index to use or 'None' [optional]

    """
    def __init__(self, ddb, **kwargs):
        """

        :param ddb:
        :param kwargs:
        """
        logging.debug('connecting to table:{0}'.format(self.table_name))
        gi = []
        keys = kwargs.keys()
        if 'item' not in keys:
            if self.email_index:
                gi.append(self.email_index)
            if self.username_index:
                gi.append(self.username_index)

            self.table = Table(
                table_name=self.table_name,
                global_indexes=gi,
                connection=ddb
            )
            # data = {}
            if 'id' in keys:
                data = {self.user_id_attribute: '{0}'.format(kwargs.get('id'))}
            else:
                data = {self.user_id_attribute: '{0}'.format(uuid.uuid4())}

            for key, value in kwargs.items():
                data[key] = value
            self._item = Item(self.table, data=data)
        else:
            self._item = kwargs.get('item')

    def __getattr__(self, item):
        return self._item[item]

    @property
    def id(self):
        return self._item[self.user_id_attribute]

    @id.setter
    def id(self, value):
        self._item[self.user_id_attribute] = value

    @property
    def email(self):
        return self._item[self.email_attribute]

    @email.setter
    def email(self, value):
        self._item[self.email_attribute] = value

    @property
    def active(self):
        return self._item[self.active_attribute]

    @active.setter
    def active(self, value):
        self._item[self.active_attribute] = value

    @property
    def roles(self):
        roles = set()
        rs = self._item[self.roles_attribute]
        logging.debug('user_id: {0}, roles: {1}'.format(self.id, rs))
        if rs:
            for role in rs:
                r = DynamoRole(role)
                roles.add(r)
                logging.debug('added DynamoRole: {0} to set'.format(r))
        return roles

    @roles.setter
    def roles(self, values):
        self._item['roles'] = set(values)

    def save(self):
        self._item.save()

    def delete(self):
        self._item.delete()