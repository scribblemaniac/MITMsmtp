#!/usr/bin/env python3

from .authMethod import authMethod
import re
import base64
import email.utils

"""
Class to handle authMethod CRAM-MD5
"""

class authCRAMMD5(authMethod):
    """Creates new authMethod object
    @type SMTPHandler: SMTPHandler
    @param SMTPHandler: SMTPHandler Object
    @type authLine: str
    @param authLine: Sent line by client for authentication
    """
    def __init__(self, SMTPHandler, authLine):
        super().__init__(SMTPHandler, authLine)

        self.SMTPHandler = SMTPHandler
        self.authLine = authLine

        self.challenge = None

        self.sendChallenge()
        self.readResponse()
        self.acceptAuth()

    """ Returns the authMethods name
    @returns: The authMethods name
    """
    @staticmethod
    def toString():
        return "CRAM-MD5"

    """Checks if the chosen methods sent by the client equals to this method

    @type methodLine: str
    @param methodLine: The method sent by client
    @returns: True in case of matching, otherwise False
    """
    @staticmethod
    def matchMethod(authLine):
        match = re.match("AUTH CRAM-MD5", authLine, re.IGNORECASE)
        return match is not None

    ###############################################
    #           AUTHENTICATION SECTION            #
    # Custom methods for this authentication Type #
    ###############################################

    """
    Sends the challenge
    """
    def sendChallenge(self):
        challenge = self.SMTPHandler.server.CRAMMD5Challenge
        if challenge is None:
            challenge = email.utils.make_msgid(domain=self.SMTPHandler.server.name)
            challenge = base64.b64encode(challenge.encode("ASCII")).decode("ASCII")
        self.SMTPHandler.writeLine(f"334 " + challenge)
        self.challenge = challenge

    """
    Reads the response to challenge
    """
    def readResponse(self):
        response = self.SMTPHandler.readLine()
        splitResponse = base64.b64decode(response).decode("ASCII").split(" ")
        if len(splitResponse) != 2:
            raise ValueError("Invalid response")

        self.username = splitResponse[0]
        self.password =  f"$cram_md5${self.challenge}${response}"

    """
    Send success message
    """
    def acceptAuth(self):
        self.SMTPHandler.writeLine("235 2.7.0 Authentication successful")
