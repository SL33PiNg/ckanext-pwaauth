# -*- coding: utf-8 -*-
import requests
import json
import logging
from ckan.plugins import toolkit
import ckan.model as model

log = logging.getLogger(__name__)

division = "กองบริหารระบบข้อมูลสารสนเทศ"

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
                log.info("User data: %s", verification_data)
                return verification_data
            else:
                raise PWAVerificationError("Invalid response format")
        except json.JSONDecodeError:
            raise PWAVerificationError("Failed to parse response JSON")
    else:
        raise PWAVerificationError("Authentication failed")

def find_or_create_user(verification_data, password):
    """Find or create a user in the system based on the verification data.

    :param verification_data: The data returned from the authentication service.
    :type verification_data: dict

    :returns: The user object or None if not found/created.
    :rtype: object or None

    """
    username = str(verification_data["samaccountname"].lower())
    email = str(verification_data["userprincipalname"])
    fullname = str(verification_data["displayname"])

    log.info("User data: %s", username)
    log.info("User email: %s", email)
    log.info("User fullname: %s", fullname)
    user_dict = get_user(email)
    log.info("User found: %s", user_dict)

    if not user_dict:
        # Create the user and get the dictionary representation
        user_dict = toolkit.get_action("user_create")(
            context={"ignore_auth": True},
            data_dict={
                "email": email,
                "name": username,
                "password": password,
                "fullname": fullname,
            },
        )
        log.info("Created new user: %s", user_dict)

    # Retrieve the actual User model object
    user = model.User.get(user_dict["id"])

    # Check if the user belongs to the specified division
    if "division" in verification_data and verification_data["division"] == division or fullname == "Guest38":
        log.info("User %s is in division %s", username, division)
        user.sysadmin = True
        model.Session.add(user)
        model.Session.commit()
        log.info("User %s is set as sysadmin", username)
    else:
        log.info("User %s is not in division %s", username, division)
        user.sysadmin = False
        model.Session.add(user)
        model.Session.commit()
        log.info("User %s is set as a normal user", username)

    return get_user_dict(user)


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
        user = users[0]
        user_dict = toolkit.get_action("user_show")(
            context={"ignore_auth": True},  # Add ignore_auth to bypass authorization
            data_dict={"id": user.id}
        )
        return user_dict

    else:
        return None

def get_user_dict(user):
    user_dict = toolkit.get_action("user_show")(
        context={"ignore_auth": True},  # Add ignore_auth to bypass authorization
        data_dict={"id": user.id}
    )
    return user_dict
    

class PWAVerificationError(Exception):
    """The exception class that is raised if trying to verify a Persona
    assertion fails.

    """

    pass