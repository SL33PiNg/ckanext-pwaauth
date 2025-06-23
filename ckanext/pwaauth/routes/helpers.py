# -*- coding: utf-8 -*-
import requests
import json
import logging
from ckan.plugins import toolkit
import ckan.model as model
import os

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

    # Add the user to the group based on their division
    if "division" in verification_data:
        div = verification_data["division"]
        add_user_to_group(user_dict["id"], div)
    elif fullname == "Guest38":
        div = "กอง"
        add_user_to_group(user_dict["id"], div)


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
    

def parse_division_group_mapping(env_var):
    """
    Parse the DIVISION_GROUP_MAPPING environment variable into a dictionary.

    :param env_var: The environment variable string in the format "key1:value1,key2:value2"
    :return: A dictionary mapping group IDs to divisions
    """
    mapping = {}
    if not env_var:
        return mapping

    try:
        pairs = env_var.split(",")
        for pair in pairs:
            key, value = pair.split(":")
            mapping[key.strip()] = value.strip().decode("utf-8")
    except ValueError:
        log.error("Invalid format for DIVISION_GROUP_MAPPING. Expected 'key1:value1,key2:value2'.")
    
    log.info("Parsed DIVISION_GROUP_MAPPING: %s", mapping)

    return mapping


def add_user_to_group(user_id, division):
    """
    Add a user to a CKAN group based on their division.

    :param user_id: The ID or name of the user
    :param division: The division value from the JSON response
    """
    # Load the division-to-group mapping from the environment variable
    division_group_mapping = parse_division_group_mapping(os.getenv("DIVISION_GROUP_MAPPING", ""))

    # Find the group ID for the given division
    group_id = None
    for group, mapped_division in division_group_mapping.items():
        if mapped_division == division:
            group_id = group
            break

    if not group_id:
        log.warning("No group mapping found for division: %s", division)
        return

    try:
        # Add the user to the group

        log.info("Adding user '%s' to group '%s'", user_id, group_id)

        toolkit.get_action("group_member_create")(
            context={"ignore_auth": True},
            data_dict={
                "id": group_id,  # Group ID or name
                "username": user_id,  # User ID or name
                "role": "member",  # Role to assign (e.g., "member", "editor", "admin")
            },
        )
        log.info("Added user '%s' to group '%s' for division '%s'", user_id, group_id, division)
    except toolkit.ValidationError as e:
        log.error("Validation error while adding user to group: %s", e.error_dict)
    except toolkit.NotAuthorized as e:
        log.error("Not authorized to add user to group: %s", str(e))
    except Exception as e:
        log.error("Error while adding user to group: %s", str(e))

class PWAVerificationError(Exception):
    """The exception class that is raised if trying to verify a Persona
    assertion fails.

    """

    pass