import oci
import sys
import traceback
import logging

def list_secrets(compartment_id, vault_client, src_vault_id, secrets_client):
    secrets_list_response = {}
    try:
        paginator = vault_client.list_secrets(compartment_id=compartment_id, vault_id=src_vault_id)
        for page in paginator.data:
                secrets_info = {}     
                secrets_info["vault_id"] = page.vault_id
                secrets_info["secret_name"] = page.secret_name
                secrets_info["lifecycle_state"] = page.lifecycle_state
                secrets_info["key_id"] = page.key_id
                secrets_info["secret_ocid"] = page.id
                secrets_info["freeform_tags"] = page.freeform_tags
                secrets_info["description"] = page.description
                secrets_info["time_of_deletion"] = paginator.data[0].time_of_deletion 
                if page.lifecycle_state == 'ACTIVE':
                    get_secret_bundle_by_name_response = secrets_client.get_secret_bundle(secret_id=page.id, stage="LATEST")
                    secrets_info["secret_bundle_content"] = get_secret_bundle_by_name_response.data.secret_bundle_content.content
                    secrets_info["secret_bundle_content_type"] = get_secret_bundle_by_name_response.data.secret_bundle_content.content_type
                    secrets_info["secret_stages"] = get_secret_bundle_by_name_response.data.stages
                    secrets_info["version_number"] = get_secret_bundle_by_name_response.data.version_number
                
                secrets_list_response[page.secret_name] = secrets_info

    except Exception as e:
        print(f"Error listing secrets: {e}")

    return secrets_list_response

def get_vault(kms_vault_client, compartment_id):
    vault_list = {}
    try:
        vault_resp = kms_vault_client.list_vaults(compartment_id)
        for v in vault_resp.data:
            vault_data = {}
            vault_data["display_name"] = v.display_name
            vault_data["freeform_tags"] = v.freeform_tags
            vault_data["management_endpoint"] = v.management_endpoint
            vault_data["vault_type"] = v.vault_type
            vault_data["vault_id"] = v.id
            vault_data["lifecycle_state"] = v.lifecycle_state
            vault_list[v.display_name] = vault_data
    except Exception as e:
        print(f"Error getting vaults: {e}")

    return vault_list

def create_vault(compartment_id, vault_info, kms_vault_client_composite):    
    try:        
        dest_vault_name = "Backup-" + vault_info["display_name"] + "-" + vault_info["vault_id"].split('.')[-3]
        print("  Creating vault {} in {} compartment".format(dest_vault_name, compartment_id))
        vault_details = oci.key_management.models.CreateVaultDetails(
            compartment_id=compartment_id,
            vault_type=vault_info["vault_type"],
            display_name=dest_vault_name,
            freeform_tags=vault_info["freeform_tags"]
        )

        response = kms_vault_client_composite.create_vault_and_wait_for_state(
            vault_details,
            wait_for_states=[oci.key_management.models.Vault.LIFECYCLE_STATE_ACTIVE]
        )
        return response
    except Exception as e:
        print(f"Error creating vault: {e}")
        return None

def create_secret(vaults_management_client_composite, compartment_id, vault_id, key_id, secret_details):
    try:
        if 'PENDING' in secret_details['secret_stages']:
            print("Latest version of Secret {} is in 'Pending' stage and it will be replicated as Active version".format(secret_details["secret_name"]))
            
        secret_content_details = oci.vault.models.Base64SecretContentDetails(
            content_type=oci.vault.models.SecretContentDetails.CONTENT_TYPE_BASE64,
            name=secret_details["secret_name"],
            stage='CURRENT',
            content=secret_details['secret_bundle_content']
        )

        secrets_details = oci.vault.models.CreateSecretDetails(
            compartment_id=compartment_id,
            description=secret_details['description'],
            secret_content=secret_content_details,
            secret_name=secret_details["secret_name"],
            vault_id=vault_id,
            key_id=key_id,
            freeform_tags=secret_details["freeform_tags"]
        )

        response = vaults_management_client_composite.create_secret_and_wait_for_state(
            create_secret_details=secrets_details,
            wait_for_states=[oci.vault.models.Secret.LIFECYCLE_STATE_ACTIVE]
        )
        return response
    except Exception as e:
        print(f"Error creating secret: {e}")
        return None

def create_key(key_mgmt_composite, dst_key_name, compartment_id):
    try:
        print("Creating KMS key {} in compartment {}.".format(dst_key_name, compartment_id))

        key_shape = oci.key_management.models.KeyShape(algorithm="AES", length=32)
        key_details = oci.key_management.models.CreateKeyDetails(
            compartment_id=compartment_id,
            display_name=dst_key_name,
            key_shape=key_shape
        )

        response = key_mgmt_composite.create_key_and_wait_for_state(
            key_details,
            wait_for_states=[oci.key_management.models.Key.LIFECYCLE_STATE_ENABLED]
        )
        return response
    except Exception as e:
        print(f"Error creating key: {e}")
        return None

def list_keys(key_management_client,compartment_id):
    try:
        list_keys_response = key_management_client.list_keys(compartment_id=compartment_id)            
    except Exception as e:
        print(f"An error occurred: {e}")
    return list_keys_response

def update_secret(vaults_management_client_composite,secret_details,secret_id):
    try:
        '''
        [Bug?]When i tried to update FreeForm Tags, getting below error
        The following tag namespaces / keys are not authorized or not found: 'oracle-tags''oracle'
        '''
        Stage='CURRENT'
        if 'PENDING' in secret_details['secret_stages']:
            logging.getLogger().info(f"[INFO]Latest version of Secret {secret_details['secret_name']} is in 'Pending' stage")
            Stage='PENDING'
        secret_content_details = oci.vault.models.Base64SecretContentDetails(
            content_type=oci.vault.models.SecretContentDetails.CONTENT_TYPE_BASE64,
            stage=Stage,
            content=secret_details['secret_bundle_content']
        )
        secrets_details = oci.vault.models.UpdateSecretDetails(
            description=secret_details['description'],
            secret_content=secret_content_details
        )
        response = vaults_management_client_composite.update_secret_and_wait_for_state(
        secret_id=secret_id,
        update_secret_details=secrets_details,
        wait_for_states=[oci.vault.models.Secret.LIFECYCLE_STATE_ACTIVE]
        )
        return response
    except Exception as e:
        logging.getLogger().info(f"[Error]update_secret - {e}")
        return None

def schedule_secret_deletion(dst_secrets_client,dst_vaults_client, secret_id, deletion_time):
    print("Deleting a secret")
    #Get secret info to get time of deletion    
    schedule_secret_deletion_response = dst_vaults_client.schedule_secret_deletion(
        secret_id=secret_id,
        schedule_secret_deletion_details=oci.vault.models.ScheduleSecretDeletionDetails(
            time_of_deletion=deletion_time))

# User parameters
compartment_id = "ocid1.compartment.oc1..aaaaaaaabldey3l2ymkpjs7jlnpbcmadlhlze2qbbbehbezhbzxvzxvnttya"
dest_vault_endpoint = "https://kms.uk-london-1.oraclecloud.com"  #https://docs.oracle.com/en-us/iaas/api/#/en/key/release/
dest_vault_secret_endpoint = "https://vaults.uk-london-1.oci.oraclecloud.com" #https://docs.oracle.com/en-us/iaas/api/#/en/secretmgmt/20180608/
dest_vault_secret_retrieval_endpoint="https://secrets.vaults.uk-london-1.oci.oraclecloud.com" #https://docs.oracle.com/en-us/iaas/api/#/en/secretretrieval/20190301/
dst_key_name = 'secret-replication-key'
config = oci.config.from_file("~/.oci/config")

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
    src_vault_list = get_vault(src_kms_vault_client, compartment_id)
    #ensure the vault is not present in destination region. 
    dst_vault_list = get_vault(dst_kms_vault_client, compartment_id) 
    # Step 2: Creating vaults in the secondary region
    for src_vault_info in src_vault_list.values():
        if src_vault_info["lifecycle_state"] == 'ACTIVE':
            #avoid creating duplicate Vaults
            dest_vault_name = "Backup-" + src_vault_info["display_name"] + "-" + src_vault_info["vault_id"].split('.')[-3]
            dst_vault_presence=False 
            for vault_name,vault_info in dst_vault_list.items():
                if vault_name == dest_vault_name:
                    dst_vault_presence=True
                    break 
            
            if dst_vault_presence == True:
                ext_dst_vault=dst_vault_list[dest_vault_name]
                dst_vault_id=ext_dst_vault["vault_id"]
                dst_vault_management_endpoint=ext_dst_vault["management_endpoint"]
                print("[Warning] Vault {} exists in Dest region {}".format(ext_dst_vault['display_name'], ext_dst_vault['vault_id'].split('.')[-3]))
                # Step 2.1: Validating KMS key in the destination to avoid duplicates                
                dst_vault_management_client = oci.key_management.KmsManagementClient(config, service_endpoint=dst_vault_management_endpoint)
                dst_list_keys=list_keys(dst_vault_management_client,compartment_id)
                key_flag=False
                for key_dtls in dst_list_keys.data:
                    if key_dtls.display_name == dst_key_name and key_dtls.lifecycle_state == 'ENABLED':
                        dst_key_id=key_dtls.id
                        key_flag=True
                        break
                if  key_flag == False:
                    # Step 2.1: Creating KMS key in the destination                
                    dst_vault_management_client = oci.key_management.KmsManagementClient(config, service_endpoint=dst_vault_management_endpoint)
                    dst_vault_management_client_composite = oci.key_management.KmsManagementClientCompositeOperations(dst_vault_management_client)
                    key = create_key(dst_vault_management_client_composite, dst_key_name, compartment_id).data
                    dst_key_id = key.id
                else:
                    print("[Warning] Key {} exists in Dest region".format(dst_key_name))
            else:
                dst_vault = create_vault(compartment_id, src_vault_info, dst_kms_vault_client_composite).data
                print("Created Vault {} in Dest region {}".format(dst_vault.display_name, dst_vault.id.split('.')[-3]))
                dest_vault_create=True
                dst_vault_id=dst_vault.id
                dst_vault_management_endpoint=dst_vault.management_endpoint
                # Step 2.1: Creating KMS key in the destination                
                dst_vault_management_client = oci.key_management.KmsManagementClient(config, service_endpoint=dst_vault_management_endpoint)
                dst_vault_management_client_composite = oci.key_management.KmsManagementClientCompositeOperations(dst_vault_management_client)
                key = create_key(dst_vault_management_client_composite, dst_key_name, compartment_id).data
                dst_key_id = key.id

            # Step 3: Replicating secrets from source to destination
            print("Retrieving secrets from Source vault {}".format(src_vault_info["display_name"]))
            src_list_secrets_response = list_secrets(compartment_id, src_vault_client, src_vault_info["vault_id"], src_secrets_client)
            dst_list_secrets_response = list_secrets(compartment_id, dst_vaults_client, dst_vault_id, dst_secrets_client)
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
                    create_secret_key_response = create_secret(dst_vaults_management_client_composite, compartment_id, dst_vault_id, dst_key_id, secret_dtls).data
                    print("Created Secret {}".format(create_secret_key_response.secret_name))
                elif dst_secret_presence == True and secret_dtls["lifecycle_state"] == 'ACTIVE':
                    update_secret(dst_vaults_management_client_composite,secret_dtls,dst_secret_id)  
                    print("[Info]  Secret {} already present in dest vault, updating the secret".format(secret_name))
                elif dst_secret_presence == True and secret_dtls["lifecycle_state"] == 'PENDING_DELETION' :                    
                    if dst_secret_state == 'ACTIVE':
                        schedule_secret_deletion(dst_secrets_client,dst_vaults_client, dst_secret_id, secret_dtls['time_of_deletion'])
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

