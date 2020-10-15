"""
Autopsy Forensic Browser
Copyright 2019-2020 Basis Technology Corp.
Contact: carrier <at> sleuthkit <dot> org
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from java.sql import SQLException
from java.util.logging import Level
from java.util import ArrayList
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import AppSQLiteDB
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskCoreException
from org.sleuthkit.datamodel.Blackboard import BlackboardException
from org.sleuthkit.autopsy.casemodule import NoCurrentCaseException
from org.sleuthkit.datamodel.blackboardutils import CommunicationArtifactsHelper
from TskMessagesParser import TskMessagesParser
from TskContactsParser import TskContactsParser
from org.sleuthkit.datamodel import CommunicationsManager 

import traceback
import general
import json

class TinderAnalyzer(general.AndroidComponentAnalyzer):
    """
        Parses the Tinder databases for TSK contact, message 
        and calllog artifacts.
    """

    def __init__(self):
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._TINDER_PACKAGE_NAME = "com.tinder"
        self._PARSER_NAME = "Tinder Parser"
        self._VERSION = ""

        communication_manager = Case.getCurrentCase().getSleuthkitCase().getCommunicationsManager()

        self.account = CommunicationsManager.addAccountType(communication_manager,"Tinder", "Tinder")

    def analyze(self, dataSource, fileManager, context):
        self.dataSource = dataSource
        """
            Extract, Transform and Load all TSK contact, message
            and calllog artifacts from the Tinder databases.
        """
        try:
            calllog_and_message_dbs = AppSQLiteDB.findAppDatabases(dataSource,
                    "tinder-3.db", False, self._TINDER_PACKAGE_NAME)

            contact_dbs = AppSQLiteDB.findAppDatabases(dataSource,
                    "tinder-3.db", True, self._TINDER_PACKAGE_NAME)
            
            # Extract TSK_CONTACT information
            for contact_db in contact_dbs:
                current_case = Case.getCurrentCaseThrows()
                helper = CommunicationArtifactsHelper(
                        current_case.getSleuthkitCase(), self._PARSER_NAME,
                        contact_db.getDBFile(), self.account)
                self.parse_contacts(contact_db, helper)

            for calllog_and_message_db in calllog_and_message_dbs:
                current_case = Case.getCurrentCaseThrows()
                helper = CommunicationArtifactsHelper(
                        current_case.getSleuthkitCase(), self._PARSER_NAME,
                        calllog_and_message_db.getDBFile(), self.account)
                # self.parse_calllogs(calllog_and_message_db, helper)
                self.parse_messages(calllog_and_message_db, helper)

        except NoCurrentCaseException as ex:
            #If there is no current case, bail out immediately.
            self._logger.log(Level.WARNING, "No case currently open.", ex)
            self._logger.log(Level.WARNING, traceback.format_exec())
        
        # Clean up open file handles.
        for contact_db in contact_dbs:
            contact_db.close()

        for calllog_and_message_db in calllog_and_message_dbs:
            calllog_and_message_db.close()

    def parse_contacts(self, contacts_db, helper):
        try:
            contacts_parser = TinderContactsParser(contacts_db)
            while contacts_parser.next():
                helper.addContact(
                contacts_parser.get_contact_name(),
                contacts_parser.get_phone(),
                contacts_parser.get_home_phone(),
                contacts_parser.get_mobile_phone(),
                contacts_parser.get_email(),
                contacts_parser.get_other_attributes()
                )
                
            contacts_parser.close()

        except SQLException as ex:
            self._logger.log(Level.WARNING, "Error querying the Tinder database for contacts.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())
        except TskCoreException as ex:
            self._logger.log(Level.SEVERE, 
                    "Error adding Tinder contact artifacts to the case database.", ex)
            self._logger.log(Level.SEVERE, traceback.format_exc())
        except BlackboardException as ex:
            self._logger.log(Level.WARNING, 
                    "Error posting contact artifact to the blackboard.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())

    def parse_messages(self, database, helper):
        try:
            messages_parser = TinderMessagesParser(database)
            while messages_parser.next():
                helper.addMessage(
                                        messages_parser.get_message_type(),
                                        messages_parser.get_message_direction(),
                                        messages_parser.get_phone_number_from(),
                                        messages_parser.get_phone_number_to(),
                                        messages_parser.get_message_date_time(),
                                        messages_parser.get_message_read_status(),
                                        messages_parser.get_message_subject(),
                                        messages_parser.get_message_text(),
                                        messages_parser.get_thread_id()
                                    )
            messages_parser.close()
        except SQLException as ex:
            self._logger.log(Level.WARNING, "Error querying the tinder database for contacts.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())
        except TskCoreException as ex:
            self._logger.log(Level.SEVERE, 
                    "Error adding tinder contact artifacts to the case database.", ex)
            self._logger.log(Level.SEVERE, traceback.format_exc())
        except BlackboardException as ex:
            self._logger.log(Level.WARNING, 
                    "Error posting contact artifact to the blackboard.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())

class TinderContactsParser(TskContactsParser):
    """
        Extracts TSK_CONTACT information from the Tinder database.
        TSK_CONTACT fields that are not in the Tinder database are given 
        a default value inherited from the super class. 
    """

    def __init__(self, contact_db):
        super(TinderContactsParser, self).__init__(contact_db.runQuery(
            """
                    select match_id, match_creation_date/1000 , match_last_activity_date, match_person_id, match_person_name, match_person_bio, match_person_birth_date/1000, case when match_is_blocked = 1 then 'Blocked' when match_is_blocked = 0 then 'Not Blocked ' else 'Invalid' end from match_view;"
            """                                                         
            )
        )
    
    def get_other_attributes(self):
        additionalAttributes = ArrayList()
        additionalAttributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID, "Tinder Parser", self.result_set.getString("match_person_id")))
        return additionalAttributes
    
    def get_contact_name(self):
        return self.result_set.getString("match_person_name")

class TinderMessagesParser(TskMessagesParser):
    """
        Extract TSK_MESSAGE information from the Tinder database.
        TSK_CONTACT fields that are not in the TInder database are given
        a default value inherited from the super class. 
    """

    def __init__(self, message_db):
        super(TinderMessagesParser, self).__init__(message_db.runQuery(
            """
                    select message_to_id, message_from_id , message_text, message_sent_date, message_is_seen, message_delivery_status from message_view order by message_sent_date;
            """
            )
        )
        self._TINDER_MESSAGE_TYPE = "Tinder Message"


    def get_message_type(self):
        return self._TINDER_MESSAGE_TYPE


    def get_phone_number_to(self):
        return self.result_set.getString("message_to_id")

    def get_phone_number_from(self):
        return self.result_set.getString("message_from_id")

    def get_message_direction(self):
        sender = str(self.result_set.getLong("message_from_id"))
        self.uid = ""
        if self.uid == sender:
            return self.OUTGOING
        return self.INCOMING

    def get_message_date_time(self):
        return self.result_set.getLong("message_sent_date") / 1000

    def get_message_text(self):
        return self.result_set.getString("message_text")

    def get_message_read_status(self):
        if self.get_message_direction() == self.INCOMING: 
            if self.result_set.getInt("message_is_seen") == 1:
                return self.READ
            else:
                return self.UNREAD
        return super(TinderMessagesParser, self).get_message_read_status()

    