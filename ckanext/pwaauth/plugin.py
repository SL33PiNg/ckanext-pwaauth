import logging
# import ckan.plugins as p
from ckan.plugins import SingletonPlugin, implements, interfaces, toolkit
import ckan.plugins.toolkit as toolkit
from ckan.common import session, request
from ckanext.pwaauth.routes.login import blueprint

try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs

log = logging.getLogger(__name__)

class PwaauthAuthenticator(SingletonPlugin):
    implements(interfaces.IConfigurer)
    implements(interfaces.IBlueprint, inherit=True)
    implements(interfaces.IAuthenticator)
    implements(interfaces.ITemplateHelpers, inherit=True)

    def update_config(self, config):
        """Implement IConfigurer.update_config

        Add our custom template to the list of templates so we can override the login form.
        """
        toolkit.add_template_directory(config, "templates")

    def get_helpers(self):
        return {
            'is_pwa_user': is_pwa_user,
            'get_login_action': get_login_action
        }

    def identify(self):
        """Identify which user (if any) is logged-in via PWA authentication."""
        user = session.get("ckanext-pwaauth-user")
        if user:
            log.info("PwaauthAuthenticator identify called: %s", user)
            toolkit.c.user = user
    def login(self):
        pass

    def get_blueprint(self):
        return blueprint

    def logout(self):
        """Handle a logout."""
        self._delete_session_items()
        if toolkit.check_ckan_version(min_version='2.10.0'):
            toolkit.logout_user()

    def abort(self, status_code, detail, headers, comment):
        """Handle an abort."""
        self._delete_session_items()

    def _delete_session_items(self):
        if "ckanext-pwaauth-user" in session:
            del session["ckanext-pwaauth-user"]
        session.save()

def is_pwa_user():
    """Helper function to determine if the current user is a PWA user."""
    return 'ckanext-pwaauth-user' in session

def get_login_action():
    """Returns the PWA login handler URL."""
    login_handler = getattr(toolkit.c, 'login_handler', '/pwa_login_handler')
    came_from = parse_qs(urlparse(login_handler).query).get('came_from')
    if came_from:
        action = "/pwa_login_handler?came_from=" + came_from[0]
    else:
        action = "/pwa_login_handler"
    return action

