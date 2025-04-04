from pycti import OpenCTIConnectorHelper
from parser.eml import eml_parser
from datetime import datetime
from core.plb_eml import PLBEml
from core.opencti_observable import ObservationType
from typing import List
import random
from urllib.parse import urlparse

def random_hex_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))


class PLBConnector:
    today_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        
        depoly = "EML"
        
        incident_name = f"Incident: {depoly}"
        
        self.incident = self.helper.api.case_incident.create(
            name=incident_name,
            description="Automatically created by PLAINBIT",
            created=self.today_date,
            secverity="low",
            confidence=100,
            rating="none",
            objectLabel=["PLAINBIT"]
        )
        
        self.label = ["ATTACKER-Mail"]
        self.make_label("ATTACKER-Mail")
        self.make_label("From")
        self.make_label("To")
        self.make_label("Suspicious-Link")

    def run(self):
        self.helper.log_info("PLAINBIT Connector Started")
        self._run_eml()
        # self._run_test() 

    # MAKE DATA ######################################################################
    def make_observable(self, data, label=["PLAINBIT"]):
        return self.helper.api.stix_cyber_observable.create(
            observableData=data, 
            objectLabel=label,
            createdBy="PLAINBIT",
        )
    
    def make_relationship(self, from_, to_, type_="related-to"):
        return self.helper.api.stix_core_relationship.create(
            fromId=from_, 
            toId=to_, 
            relationship_type=type_, 
            start_time=self.today_date,
            stop_time=self.today_date
        )
        
    def connect_obj_or_relationship(self, target_id, stix_id):
        self.helper.api.case_incident.add_stix_object_or_stix_relationship(
            id=target_id, 
            stixObjectOrStixRelationshipId=stix_id
        )
        
    def make_label(self, label):
        filters={
            "mode": "and",
            "filters": [
                {"key": "value", "values": [label]},
            ],
            "filterGroups": [],
        }
        result = self.helper.api.label.read(filters=filters)
        
        if result is None:
            self.helper.api.label.create(value=label, color=random_hex_color())
    
    # RUN #############################################################################
    def _run_test(self):
        eml_parser.parse_all_eml_data("Target")
    
    def _run_eml(self):
        eml_list: List[PLBEml] = eml_parser.parse_all_eml_data("Target")
        
        if not eml_list:
            self.helper.log_info("No EML Data")
            return

        for eml in eml_list:
            self.helper.log_info(f"processing: {eml.file_name}")
            print(f"\nProcess {eml}")
            
            if eml.message_id:
                email_message = {
                    "type": ObservationType.EMAIL_MESSAGE,
                    "message_id": eml.message_id,
                    "is_multipart": False,
                    "subject": eml.subject or "[No Subject]",
                    "received_lines": "",
                    "date": eml.date,
                    "body": eml.message_id,
                    "description": eml.file_name
                }
                
                ob_message = self.make_observable(email_message, self.label)
                self.connect_obj_or_relationship(self.incident['id'], ob_message['id'])
                
                if len(eml.from_) > 0:
                    email_addr = {
                        "type": ObservationType.EMAIL_ADDR,
                        "value": eml.from_,
                    }
                    
                    from_label = self.label + ["From"]

                    
                    ob_addr = self.make_observable(email_addr, from_label)
                    rel_addr = self.make_relationship(ob_message['id'], ob_addr['id'])
                    
                    self.connect_obj_or_relationship(self.incident['id'], ob_addr['id'])
                    self.connect_obj_or_relationship(self.incident['id'], rel_addr['id'])
                
                if len(eml.to_) > 0:
                    for _to in eml.to_:
                        
                        if _to == "-":
                            continue
                        
                        print(f"TO: {_to}")
                        email_addr_to = {
                            "type": ObservationType.EMAIL_ADDR,
                            "value": _to,
                        }
                        
                        to_label = self.label + ["To"]
                        
                        ob_addr_to = self.make_observable(email_addr_to, to_label)
                        self.make_relationship(ob_message['id'], ob_addr_to['id'])
                
                if len(eml.suspicious_link) > 0:
                    for _link in eml.suspicious_link:
                        
                        if "[.]" in _link:
                            _link = _link.replace("[.]", ".")
                        
                        link_data = {
                            "type": ObservationType.URL,
                            "value": _link
                        }
                        
                        label = ["Suspicious-Link"]
                        
                        ob_link = self.make_observable(link_data, label)
                        
                        print(f"{eml} | {ob_message['id']} : {ob_link['id']}")
                        rel_link = self.make_relationship(ob_message['id'], ob_link['id'])
                        self.connect_obj_or_relationship(self.incident['id'], ob_link['id'])
                        self.connect_obj_or_relationship(self.incident['id'], rel_link['id'])
                        
                        domain = self._check_domain(_link)
                        domain_data = {
                            "type": ObservationType.DOMAIN,
                            "value": domain
                        }
                        
                        ob_domain = self.make_observable(domain_data, label)
                        rel_domain = self.make_relationship(ob_link['id'], ob_domain['id'])
                        
                        self.connect_obj_or_relationship(self.incident['id'], ob_domain['id'])
                        self.connect_obj_or_relationship(self.incident['id'], rel_domain['id'])

    def _check_domain(self, url):
        return urlparse(url.replace("hxxp", "http", 1)).netloc
    