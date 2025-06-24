from flask import Blueprint
from ckan.plugins import toolkit
import logging
from ckan.common import session
from ckanext.pwaauth.routes.helpers import verify_login, PWAVerificationError, find_or_create_user
from ckan.model import User

log = logging.getLogger(__name__)

blueprint = Blueprint(name='pwa', import_name=__name__)

@blueprint.route('/pwa_login_handler', methods=['POST'])
def login_handler():
    log.info("Pwaauth Route login_handler called")
    params = toolkit.request.values
    came_from = params.get('came_from', None)

    # Ensure came_from has a default value if None
    if not came_from or not isinstance(came_from, str):
        came_from = "/"

    if "login" in params and "password" in params:  
        try:
            login = params["login"]
            password = params["password"]

            log.info("Pwaauth Route login_handler called with login: %s", login)
            verification_data = verify_login(login, password)
            user = find_or_create_user(verification_data, password)
            
            log.info("User found: %s", user)

            return _login_success(user["name"], came_from=came_from)
        except PWAVerificationError as e:
            # Handle PWA verification error
            log.info("Pwaauth Route login_handler failed with PWAVerificationError: %s", str(e))
            
            try:
                log.info("Attempting to find CKAN user with login: %s", login)
                user_dict = get_user_dict(login)
                log.info("CKAN user found: %s", user_dict)
                user = User.by_name(user_dict['name'])
                log.info("User object retrieved: %s", user)
            except toolkit.ObjectNotFound:
                user = None
            log.info("validating with password: %s", password)
            log.info("validating result %s", user.validate_password(password))
            if user and user.validate_password(password):
                return _login_success(user.name, came_from=came_from)

            log.error("Pwaauth Route login_handler failed: %s", str(e))
            toolkit.h.flash_error(str(e))
            return toolkit.redirect_to("user.login")



def _login_success(username ,came_from):
    """Handle login success."""
    redirect_path = 'home.index'
    user_login_path = 'user.login'
    err_msg = 'An error occurred while logging in. Please try again.'

    try:
        # Look up the CKAN User object for user_name
        user_obj = User.by_name(username)
    except toolkit.ObjectNotFound as err:
        log.error(
            'User.by_name(%s) raised ObjectNotFound error: %s', username, err
        )
        toolkit.h.flash_error(err_msg)
        return toolkit.redirect_to(user_login_path)

    ok = toolkit.login_user(user_obj)

    if not ok:
      log.error(f"toolkit.login_user() returned False for user '{username}'")
      return toolkit.redirect_to(user_login_path)

    session["ckanext-pwaauth-user"] = username
    session.save()
    return toolkit.redirect_to(redirect_path, came_from=came_from)


def _login_failed(notice=None, error=None):
    """
    Handle login failures. Redirect to /user/login and flash an optional message.

    :param notice: Optional notice for the user (Default value = None)
    :param error: Optional error message for the user (Default value = None)
    """
    if notice:
        toolkit.h.flash_notice(notice)
    if error:
        toolkit.h.flash_error(error)
    return toolkit.redirect_to("user.login")

def get_user_dict(user_id):
    """
    Calls the action API to get the detail for a user given their id.

    :param user_id: The user id
    """
    context = {'ignore_auth': True}
    data_dict = {'id': user_id}
    return toolkit.get_action('user_show')(context, data_dict)