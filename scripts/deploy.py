from scripts.helpful_scripts import get_account
from brownie import Confidential, network, config

def deploy():
    account = get_account()
    Confidential_deploy = Confidential.deploy(99, {"from": account}, publish_source=config["networks"][network.show_active()].get("verify", False)
)
    

def main():
    deploy()