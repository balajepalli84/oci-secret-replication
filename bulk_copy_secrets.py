import oci
import sys
import traceback
import logging
from oci_secrets_fns import oci_secrets_fns

#create instance of secret functions class
oci_secrets_fns=oci_secrets_fns()

# User parameters
compartment_id = "ocid1.compartment.oc1..aaaaaaaabldey3l2ymkpjs7jlnpbcmadlhlze2qbbbehbezhbzxvzxvnttya"
dest_vault_endpoint = "https://kms.uk-london-1.oraclecloud.com"  #https://docs.oracle.com/en-us/iaas/api/#/en/key/release/
dest_vault_secret_endpoint = "https://vaults.uk-london-1.oci.oraclecloud.com" #https://docs.oracle.com/en-us/iaas/api/#/en/secretmgmt/20180608/
dest_vault_secret_retrieval_endpoint="https://secrets.vaults.uk-london-1.oci.oraclecloud.com" #https://docs.oracle.com/en-us/iaas/api/#/en/secretretrieval/20190301/
dst_key_name = 'secret-replication-key'
config = oci.config.from_file(file_location="~/.oci/config",profile_name="seanteam")

try:
    # Configure OCI clients
    src_secrets_client = oci.secrets.SecretsClient(config)
    dst_secrets_client = oci.secrets.SecretsClient(config,service_endpoint=dest_vault_secret_retrieval_endpoint)
    src_kms_vault_client = oci.key_management.KmsVaultClient(config)
    src_kms_vault_client_composite = oci.key_management.KmsVaultClientCompositeOperations(src_kms_vault_client)
    dst_kms_vault_client = oci.key_management.KmsVaultClient(config, service_endpoint=dest_vault_endpoint)
    dst_kms_vault_client_composite = oci.key_management.KmsVaultClientCompositeOperations(dst_kms_vault_client)
    src_vault_client = oci.vault.VaultsClient(config)
    dst_vaults_client = oci.vault.VaultsClient(config, service_endpoint=dest_vault_secret_endpoint)
    dst_vaults_management_client_composite = oci.vault.VaultsClientCompositeOperations(dst_vaults_client)

    # Step 1: Getting source Vault details
    print("Getting source Vault information.")
    src_vault_list = oci_secrets_fns.get_vaults(src_kms_vault_client, compartment_id)
    #To ensure the vault is not present in destination region, get destination vaults
    dst_vault_list = oci_secrets_fns.get_vaults(dst_kms_vault_client, compartment_id) 
    # Step 2: Validate and create vaults in the secondary region
    for src_vault_info in src_vault_list.values():
        #avoid creating duplicate Vaults
        dest_vault_name = "Backup-" + src_vault_info["display_name"] + "-" + src_vault_info["vault_id"].split('.')[-3]
        dst_vault_presence=False 
        for vault_name,vault_info in dst_vault_list.items():
            if vault_name == dest_vault_name:
                dst_vault_presence=True
                break #if vault exists, get the vault info and break the loop 

        #If the the vault exists in the destination region
        if dst_vault_presence == True:
            ext_dst_vault=dst_vault_list[dest_vault_name]
            dst_vault_id=ext_dst_vault["vault_id"]
            dst_vault_management_endpoint=ext_dst_vault["management_endpoint"]
            print("[Warning] Vault {} exists in Dest region {}".format(ext_dst_vault['display_name'], ext_dst_vault['vault_id'].split('.')[-3]))
            # Step 2.1: Validating KMS key in the destination to avoid duplicates                
            dst_vault_management_client = oci.key_management.KmsManagementClient(config, service_endpoint=dst_vault_management_endpoint)
            dst_list_keys=oci_secrets_fns.list_keys(dst_vault_management_client,compartment_id)
            key_flag=False
            for key_dtls in dst_list_keys.data:
                if key_dtls.display_name == dst_key_name and key_dtls.lifecycle_state == 'ENABLED':
                    dst_key_id=key_dtls.id
                    key_flag=True
                    break #if key exists, get the key id and break the loop 
            if  key_flag == False:
                # Step 2.1: Creating KMS key in the destination                
                dst_vault_management_client = oci.key_management.KmsManagementClient(config, service_endpoint=dst_vault_management_endpoint)
                dst_vault_management_client_composite = oci.key_management.KmsManagementClientCompositeOperations(dst_vault_management_client)
                key = oci_secrets_fns.create_key(dst_vault_management_client_composite, dst_key_name, compartment_id).data
                dst_key_id = key.id
            else:
                print("[Warning] Key {} exists in Dest region".format(dst_key_name))
        else: #if Vault doesnt exist in the destination region
            dst_vault = oci_secrets_fns.create_vault(compartment_id, src_vault_info, dst_kms_vault_client_composite).data
            print("Created Vault {} in Dest region {}".format(dst_vault.display_name, dst_vault.id.split('.')[-3]))
            dest_vault_create=True
            dst_vault_id=dst_vault.id
            dst_vault_management_endpoint=dst_vault.management_endpoint
            # Step 2.1: Creating KMS key in the destination                
            dst_vault_management_client = oci.key_management.KmsManagementClient(config, service_endpoint=dst_vault_management_endpoint)
            dst_vault_management_client_composite = oci.key_management.KmsManagementClientCompositeOperations(dst_vault_management_client)
            key = oci_secrets_fns.create_key(dst_vault_management_client_composite, dst_key_name, compartment_id).data
            dst_key_id = key.id

        # Step 3: Replicating secrets from source to destination
        print("Retrieving secrets from Source vault {}".format(src_vault_info["display_name"]))
        src_list_secrets_response = oci_secrets_fns.list_secrets(compartment_id, src_vault_client, src_vault_info["vault_id"], src_secrets_client)
        dst_list_secrets_response = oci_secrets_fns.list_secrets(compartment_id, dst_vaults_client, dst_vault_id, dst_secrets_client)
        for secret_name, secret_dtls in src_list_secrets_response.items():
            #Avoid creating duplicate secrets
            dst_secret_presence=False
            for dst_secret_name,dst_secret_dtls in dst_list_secrets_response.items():
                if dst_secret_dtls["secret_name"] == secret_name:
                    dst_secret_presence=True
                    dst_secret_id=dst_secret_dtls["secret_ocid"]
                    dst_secret_state=dst_secret_dtls["lifecycle_state"]
                    break
                    
            if dst_secret_presence == False and secret_dtls["lifecycle_state"] == 'ACTIVE':
                create_secret_key_response = oci_secrets_fns.create_secret(dst_vaults_management_client_composite, compartment_id, dst_vault_id, dst_key_id, secret_dtls).data
                print("Created Secret {}".format(create_secret_key_response.secret_name))
            elif dst_secret_presence == True and secret_dtls["lifecycle_state"] == 'ACTIVE':
                oci_secrets_fns.update_secret(dst_vaults_management_client_composite,secret_dtls,dst_secret_id)  
                print("[Info]  Secret {} already present in dest vault, updating the secret".format(secret_name))
            elif dst_secret_presence == True and secret_dtls["lifecycle_state"] == 'PENDING_DELETION' :                    
                if dst_secret_state == 'ACTIVE':
                    oci_secrets_fns.schedule_secret_deletion(dst_vaults_client, dst_secret_id, secret_dtls['time_of_deletion'])
                    print("[Info]  Marking Secret {} for deletion at {} ".format(secret_name,secret_dtls['time_of_deletion'])   )     
                else:
                    print("[Info]  Secret {} is scheduled for deletion on {}. Skipping Replication ".format(secret_name,secret_dtls['time_of_deletion'])   ) 
            else:
                print("[Error] Secret {} is in {} state. Skipping Replication".format(secret_name,secret_dtls['lifecycle_state']))


except Exception as e:
    print(f"An error occurred: {e}")
        # Display full error details using traceback
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback_details = {
        'filename': exc_traceback.tb_frame.f_code.co_filename,
        'lineno': exc_traceback.tb_lineno,
        'name': exc_traceback.tb_frame.f_code.co_name,
        'type': exc_type.__name__,
        'message': str(exc_value)
    }
    print("Exception Details:")
    for key, value in traceback_details.items():
        print(f"{key}: {value}")
    traceback.print_exception(exc_type, exc_value, exc_traceback)

