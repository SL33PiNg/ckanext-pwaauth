import logging
import ckan.plugins as p
import ckan.plugins.toolkit as toolkit
import uuid
# from flask import session
from ckan.common import session, request

try:
    # In case we are running Python3
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs


log = logging.getLogger(__name__)


class PwaauthAuthenticator(p.SingletonPlugin):
    p.implements(p.IConfigurer)
    p.implements(p.IAuthenticator)
    p.implements(p.IRoutes, inherit=True) 
    p.implements(p.ITemplateHelpers, inherit=True)

    def update_config(self, config):
        """Implement IConfiguer.update_config

        Add our custom template to the list of templates so we can override the login form.
        """
        toolkit.add_template_directory(config, "templates")
    
    def before_map(self, map):
        """Implements Iroutes.before_map

        Add our custom login form handler"""
        map.connect('/pwa_login_handler',
                    controller='ckanext.pwaauth.controller:PwaauthController',
                    action='login_handler')
        return map

    def login(self):
        """Handle an attempt to login using the new authentication service."""
        
            # return login_success(came_from=params.get("came_from", "/"))

    def identify(self):
        """Identify which user (if any) is logged-in via Persona.

        If a logged-in user is found, set toolkit.c.user to be their user name.

        """
        # Try to get the item that login() placed in the session.
        user = session.get("ckanext-pwaauth-user")
        if user:
            # We've found a logged-in user. Set c.user to let CKAN know.
            log.info("PwaauthAuthenticator identify called: %s", user)

            toolkit.c.user = user

    def _delete_session_items(self):

        if "ckanext-pwaauth-user" in session:
            del session["ckanext-pwaauth-user"]
        if "ckanext-pwaauth-email" in session:
            del session["ckanext-pwaauth-email"]
        session.save()

    def logout(self):
        """Handle a logout."""

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()

    def abort(self, status_code, detail, headers, comment):
        """Handle an abort."""

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()

    def get_helpers(self):
        return {
            'is_pwa_user': is_pwa_user,
            'get_login_action': get_login_action
        }



def is_pwa_user():
    """
    Help function for determining if current user is LDAP user
    @return: boolean
    """

    return 'ckanext-pwa-user' in session

def get_login_action():
    """Returns the PWA login handler URL. Preserves the `came_from` parameter if available."""
    # Safely get the login_handler attribute or provide a default
    login_handler = getattr(toolkit.c, 'login_handler', '/pwa_login_handler')
    came_from = parse_qs(urlparse(login_handler).query).get('came_from')
    if came_from:
        action = "/pwa_login_handler?came_from=" + came_from[0]
    else:
        action = "/pwa_login_handler"
    return action

