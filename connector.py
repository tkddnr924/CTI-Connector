import os
import yaml
import time
import sys
from pycti import OpenCTIConnectorHelper
from connector.plb_connector import PLBConnector

def set_connector():
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
    
    with open(config_file_path, encoding="utf-8") as f:
        raw_config = yaml.safe_load(f)

    config = {
        "OPENCTI_URL": raw_config["opencti"]["base_url"],
        "OPENCTI_TOKEN": raw_config["opencti"]["token"],
        "CONNECTOR_ID": raw_config["connector"]["id"],
        "CONNECTOR_TYPE": raw_config["connector"]["type"],
        "CONNECTOR_NAME": raw_config["connector"]["name"],
        "CONNECTOR_SCOPE": raw_config["connector"]["scope"],
        "CONNECTOR_CONFIDENCE_LEVEL": raw_config["connector"]["confidence_level"],
        "CONNECTOR_LOG_LEVEL": raw_config["connector"]["log_level"],
        "CONNECTOR_UPDATE_EXISTING_DATA": raw_config["connector"]["update_existing_data"]
    }
    
    return config

if __name__ == "__main__":    
    config = set_connector()
    helper = OpenCTIConnectorHelper(config)

    try:
        connector = PLBConnector(helper)
        connector.run()
    except Exception as e:
        helper.log_error(f"Connector failed: {e}")
        time.sleep(5)
        sys.exit(1)
