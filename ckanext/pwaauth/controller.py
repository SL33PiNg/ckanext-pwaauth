import ckan.plugins as p
from ckan.plugins import toolkit
import logging
import json

from ckan.common import request, session
import requests
log = logging.getLogger(__name__)

class PWAVerificationError(Exception):
    """The exception class that is raised if trying to verify a Persona
    assertion fails.

    """

    pass


class PwaauthController(p.toolkit.BaseController):
    def __init__(self, *args, **kwargs):
        log.info("PwaauthController initialized (Py2.7).")

    def login_handler(self):
        came_from = request.params.get("came_from", "/")
        if request.method == "POST":
            params = request.params

            if "login" in params and "password" in params:
                try:
                    user_data = verify_login(params["login"], params["password"])
                    username = str(user_data["samaccountname"].lower())
                    email = str(user_data["userprincipalname"])
                    fullname = str(user_data["cn"])

                    log.info("User data: %s", username)

                    user = get_user(email)

                    log.info("User: %s", user)

                    if not user:
                        user = toolkit.get_action("user_create")(
                            context={"ignore_auth": True},
                            data_dict={
                                "email": email,
                                "name": username,
                                "password": params["password"],
                                "fullname": fullname,
                            },
                        )

                    session["ckanext-pwaauth-user"] = user["name"]
                    session["ckanext-pwaauth-email"] = email
                    session.save()

                    if not came_from.startswith("/"):
                        came_from = "/"

                    return login_success(came_from=came_from)
                except PWAVerificationError as e:
                    log.error("PwaauthController login_handler failed: %s", str(e))
                    toolkit.h.flash_error(str(e))
                    return p.toolkit.redirect_to("user.login")
                # except Exception as e:
                #     log.error("PwaauthController login_handler error: %s", e)
                #     toolkit.h.flash_error(str("An error occurred during login."))
                #     return p.toolkit.redirect_to("user.login")
            else:
                return login_failed(notice="Please provide a username and password.")
        return toolkit.render("user/login.html")


def verify_login(username, password):
    """Verify the given login credentials with the provided authentication service.

    :returns: the email address or username of the successfully verified user
    :rtype: string

    :raises: :py:class:`PWAVerificationError`: if the verification fails

    """
    url = "https://nrw.pwa.co.th/ad/ver4_ad_authen_full/ad_authen.php"
    headers = {"content-type": "application/x-www-form-urlencoded"}
    data = {"username": username, "password": password, "adserver": "pwa"}

    response = requests.post(url, headers=headers, data=data)

    if response.ok:
        try:
            verification_data = response.json()
            if "samaccountname" in verification_data:
                log.info("User verified successfully")
                return verification_data
            else:
                raise PWAVerificationError("Invalid response format")
        except json.JSONDecodeError:
            raise PWAVerificationError("Failed to parse response JSON")
    else:
        raise PWAVerificationError("Authentication failed")

def login_success(came_from):
    """Handle login success."""

    return toolkit.redirect_to(
        controller="user", action="logged_in", came_from=came_from
    )


def login_failed(notice=None, error=None):
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

def get_user(email):
    """Return the CKAN user with the given email address.

    :rtype: A CKAN user dict

    """
    # We do this by accessing the CKAN model directly, because there isn't a
    # way to search for users by email address using the API yet.
    import ckan.model

    users = ckan.model.User.by_email(email)

    assert len(users) in (0, 1), (
        "The Persona plugin doesn't know what to do "
        "when CKAN has more than one user with the "
        "same email address."
    )

    if users:
        # But we need to actually return a user dict, so we need to convert it
        # here.
        user = users[0]
        user_dict = toolkit.get_action("user_show")(
            context={"ignore_auth": True},  # Add ignore_auth to bypass authorization
            data_dict={"id": user.id}
        )
        return user_dict

    else:
        return None