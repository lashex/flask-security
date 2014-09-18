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
    @staticmethod
    def _is_uuid(maybe_uuid):
        try:
            uuid.UUID(maybe_uuid)
            return True
        except ValueError as ve:
            logging.debug(
                '_is_uuid given invalid val:{0} message:{1}'.format(maybe_uuid,
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

    def __init__(self, db, user_model, role_model):
        """

        :param db: A connection to Dynamo DB
        :param user_model: A user model class definition
        :param role_model: A role model class definition
        :return:
        """
        DynamoDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)
        # self.db = dynamo_datastore
        self.user_model = user_model
        self.role_model = role_model

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
        """Finds and returns a user matching the provided parameters."""
        um = self.user_model
        keys = list(kwargs.keys())
        results = []
        if um.email_field in keys:
            email = kwargs.get(um.email_field)
            logging.debug('find_user with email: {0}'.format(email))
            if um.email_index:
                # TODO Index exists, now use it
                # results = model(self.db).user_table.query_2(
                #     self.user_model.email_field + '__eq'=email,
                #     index=model.email_index
                # )
                pass
            else:
                # Just do a scan to find the email
                kw = {
                    '{0}{1}'.format(um.email_field, '__eq'): email,
                    'limit': 1
                }
                results = self.user_model(self.db).user_table.scan(**kw)

        if self.user_model.username_field in keys:
            username = kwargs.get(um.username_field)
            logging.debug('find_user with username: {0}'.format(username))
            if um.username_index is None:
                kw = {
                    '{0}{1}'.format(um.username_field, '__eq'): username,
                    'limit': 1
                }
                results = self.user_model(self.db).user_table.scan(**kw)

        # TODO add in support for arbitrary arguments as query params

        for res in results:
            # will always return first result
            user = self.user_model(self.db)
            user.id = res[self.user_model.user_id_field]
            return user

        return None

    def create_role(self, **kwargs):
        """Creates and returns a new role from the given parameters."""
        raise NotImplementedError

    def create_user(self, **kwargs):
        # """Creates and returns a new user from the given parameters.
        #
        # :param email: the email address of the user [required]
        # :param password: the password of the user [required]
        # :param username: the username of the user
        # :param first_name: the first name of the user
        # :param last_name: the last name of the user
        # :customer_id: the customer_id within which this user is contained
        # """
        keys = list(kwargs.keys())
        if self.user_model.email_field not in keys:
            raise ValueError('email value required')

        email = kwargs.get(self.user_model.email_field)
        if not DynamoUserDatastore._is_email(email):
            raise ValueError('invalid email value:{0}'.format(email))

        if self.user_model.password_field not in keys:
            raise ValueError('password value required')

        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(self.db, **kwargs)
        return self.put(user)

    def get_user_by_id(self, user_id):
        return self.user_model(user_id)
