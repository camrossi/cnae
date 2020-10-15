# Generate and Analyse NAE Demo Data Sets

This set ansible playbook will configure and ACI fabric and deploy VMs to allow the testing and generation of dataset for Cisco NAE

## Tags

Since this is a fairly large ansible playbook all the task are tagged with one or more tags to allow for partial executions, here are the currently supported tags:

- apic_user: Create a new user and the certificates required for SSL based authentication.
- apic_config: Push baseling ACI config to APIC.
- vms: Deploy all the VMs and the external BGP router
- change_mgmt: Generate the Change Management Data Set
- dcops: Generate the Data Center Operations Data Set
- nae_config: Configure NAE, upload datasets and run epoch abalysis
- delete_apic_user: Delete the created temporary user
- cleanup: Delete ACI config, user and Destroys VMs, this will not clean up the NAE Config
- delete_tenants: Delete the ACI Tenants but leaves in place everything else. Useful if you wanna experiment with the ACI side of the config and then restore it to a known state. 
- delete_vms: Delete all the VMs, including the external BGP router
- nae_cleanup: Delete NAE Assurance Groups and Uploaded Files
