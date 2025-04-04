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

    return raw_config

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
