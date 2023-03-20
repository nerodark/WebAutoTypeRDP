""" This basic example demonstrates how to list all tabs.
"""
import json
import contextlib
from geckordp.rdp_client import RDPClient
from geckordp.actors.root import RootActor
from geckordp.profile import ProfileManager
from geckordp.firefox import Firefox


""" Uncomment to enable debug output
"""
from geckordp.settings import GECKORDP
GECKORDP.DEBUG = 1
GECKORDP.DEBUG_REQUEST = 1
GECKORDP.DEBUG_RESPONSE = 1


def main():
    try:
        #with contextlib.suppress(BaseException):
            
        port = 9444
        print("test")
        #exit()
        # create client and connect to firefox
        client = RDPClient(executor_workers=1)
        client.connect("localhost", port)
        #client.disconnect()
        # initialize root
        root = RootActor(client)
        #client.disconnect()
        # get a list of tabs
        tabs = root.list_tabs()
        print(json.dumps(tabs, indent=2))
        client.disconnect()
    except :#OSError as error :
        print("hehe")
        pass
    #exit()
    #input()


if __name__ == "__main__":
    main()
