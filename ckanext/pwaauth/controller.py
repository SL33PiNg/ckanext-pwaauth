import ckan.plugins as p
from ckan.plugins import toolkit
import logging

from ckan.common import request, session
log = logging.getLogger(__name__)
from ckanext.pwaauth.helpers import verify_login, PWAVerificationError, find_or_create_user




class PwaauthController(p.toolkit.BaseController):
    def __init__(self, *args, **kwargs):
        log.info("PwaauthController initialized")

    def login_handler(self):
        came_from = request.params.get("came_from", "/")
        if request.method == "POST":
            params = request.params

            if "login" in params and "password" in params:
                try:
                    login = params["login"]
                    password = params["password"]

                    verification_data = verify_login(login, password)
                    user = find_or_create_user(verification_data, password)
                    
                    log.info("User found: %s", user)
                    session["ckanext-pwaauth-user"] = user["name"]
                    session.save()

                    if not came_from.startswith("/"):
                        came_from = "/"

                    return self._login_success(came_from=came_from)
                except PWAVerificationError as e:
                    log.error("PwaauthController login_handler failed: %s", str(e))
                    toolkit.h.flash_error(str(e))
                    return p.toolkit.redirect_to("user.login")
                # except Exception as e:
                #     log.error("PwaauthController login_handler error: %s", e)
                #     toolkit.h.flash_error(str("An error occurred during login."))
                #     return p.toolkit.redirect_to("user.login")
            else:
                return self._login_failed(notice="Please provide a username and password.")
        return toolkit.render("user/login.html")
    
    def _login_success(self, came_from):
        """Handle login success."""

        return toolkit.redirect_to(
            controller="user", action="logged_in", came_from=came_from
        )


    def _login_failed(self, notice=None, error=None):
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





