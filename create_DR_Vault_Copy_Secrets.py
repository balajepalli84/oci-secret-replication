import io
import oci
import json
from datetime import datetime, timedelta
import logging
from fdk import response

def extract_info_from_logs(logs):

    log_entry = logs[0].get("data", {})
    compartment_id = log_entry.get("compartmentId")
    event_name = log_entry.get("eventName")
    secret_id = log_entry.get("resourceId")
    freeform_Tags=log_entry.get("freeformTags")
    secret_name=log_entry.get("source")

    return compartment_id,event_name,secret_id,freeform_Tags,secret_name

def get_vault(kms_vault_client, vault_id):
    vault_list = {}
    try:
        vault_resp = kms_vault_client.get_vault(vault_id=vault_id)
    except Exception as e:
        logging.getLogger().info(f"[Error]get_vault - Error : {e}")

    return vault_resp

def list_vault(kms_vault_client, compartment_id,vault_name):
    try:
        vault_resp = kms_vault_client.list_vaults(compartment_id)
        vault_data = {}
        for v in vault_resp.data:            
            if v.display_name == vault_name and v.lifecycle_state == 'ACTIVE':                
                vault_data["display_name"] = v.display_name
                vault_data["freeform_tags"] = v.freeform_tags
                vault_data["management_endpoint"] = v.management_endpoint
                vault_data["vault_type"] = v.vault_type
                vault_data["vault_id"] = v.id
                vault_data["lifecycle_state"] = v.lifecycle_state
                break
    except Exception as e:
        logging.getLogger().info(f"[Error]list_vault - {e}")

    return vault_data

def get_secret (secrets_client,vault_client,secret_id):
    secrets_info = {}
    secret_data=vault_client.get_secret(secret_id=secret_id)  
    secrets_info["vault_id"] = secret_data.data.vault_id
    secrets_info["secret_name"] = secret_data.data.secret_name
    secrets_info["lifecycle_state"] = secret_data.data.lifecycle_state
    secrets_info["key_id"] = secret_data.data.key_id
    secrets_info["secret_ocid"] = secret_data.data.id
    secrets_info["freeform_tags"] = secret_data.data.freeform_tags
    secrets_info["description"] = secret_data.data.description   
    #secret_bundle_content library will only work for Active Secrets
    if secret_data.data.lifecycle_state == 'ACTIVE':        
        get_secret_bundle_by_name_response = secrets_client.get_secret_bundle(secret_id=secret_id, stage="LATEST")
        secrets_info["secret_bundle_content"] = get_secret_bundle_by_name_response.data.secret_bundle_content.content
        secrets_info["secret_bundle_content_type"] = get_secret_bundle_by_name_response.data.secret_bundle_content.content_type
        secrets_info["secret_stages"] = get_secret_bundle_by_name_response.data.stages
        secrets_info["version_number"] = get_secret_bundle_by_name_response.data.version_number  
    elif secret_data.data.lifecycle_state == 'PENDING_DELETION':        
        secrets_info["time-of-deletion"] = secret_data.data.time_of_deletion  
    else:
        logging.getLogger().info(f"[Error] Secret {secret_data.data.secret_name} is in {secret_data.data.lifecycle_state} State")
    
    return secrets_info

def create_vault(compartment_id, vault_info, kms_vault_client_composite):    
          
        logging.getLogger().info(f"[Info] Vault info {vault_info.data}")
        dest_vault_name = "Backup-" + vault_info.data.display_name + "-" + vault_info.data.id.split('.')[-3]
        logging.getLogger().info(f"[Info] Creating vault {dest_vault_name} in {compartment_id} compartment")
        vault_details = oci.key_management.models.CreateVaultDetails(
            compartment_id=compartment_id,
            vault_type=vault_info.data.vault_type,
            display_name=dest_vault_name,
            freeform_tags=vault_info.data.freeform_tags
        )

        response = kms_vault_client_composite.create_vault_and_wait_for_state(
            vault_details,
            wait_for_states=[oci.key_management.models.Vault.LIFECYCLE_STATE_ACTIVE]
        )
        return response


def get_secret_by_name(compartment_id, vault_client,secret_name, vault_id, secrets_client):
    paginator = vault_client.list_secrets(compartment_id=compartment_id, vault_id=vault_id,name=secret_name)   
    secrets_info = {}
    if paginator.data:
        secrets_info['vault_id'] = paginator.data[0].vault_id
        secrets_info["secret_name"] = paginator.data[0].secret_name
        secrets_info["lifecycle_state"] = paginator.data[0].lifecycle_state
        secrets_info["key_id"] = paginator.data[0].key_id
        secrets_info["secret_ocid"] = paginator.data[0].id
        secrets_info["freeform_tags"] = paginator.data[0].freeform_tags
        secrets_info["description"] = paginator.data[0].description 
        secrets_info["time_of_deletion"] = paginator.data[0].time_of_deletion        
        if paginator.data[0].lifecycle_state == 'ACTIVE':                
            get_secret_bundle_by_name_response = secrets_client.get_secret_bundle(secret_id=paginator.data[0].id, stage="LATEST")
            secrets_info["secret_bundle_content"] = get_secret_bundle_by_name_response.data.secret_bundle_content.content
            secrets_info["secret_bundle_content_type"] = get_secret_bundle_by_name_response.data.secret_bundle_content.content_type
            secrets_info["secret_stages"] = get_secret_bundle_by_name_response.data.stages
            secrets_info["version_number"] = get_secret_bundle_by_name_response.data.version_number                             
        else:                
            logging.getLogger().info(f"[Warning] Secret {paginator.data[0].secret_name} is in {paginator.data[0].lifecycle_state} state and cannot be replicated or updated")
       
    return secrets_info

def create_secret(vaults_management_client_composite, compartment_id, vault_id, key_id, secret_details):
    try:
        if 'PENDING' in secret_details['secret_stages']:
            logging.getLogger().info(f"[Info]Latest version of Secret {secret_details['secret_name']} is in 'Pending' stage and it will be replicated as Active version")
        else:    
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
        logging.getLogger().info(f"[Error] Creating secret: {e}")
        return None

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

def create_key(key_mgmt_composite, dst_key_name, compartment_id):
    try:
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
        logging.getLogger().info(f"[Error]create_key - {e}")
        return None

def list_keys(key_management_client,compartment_id):
    try:
        list_keys_response = key_management_client.list_keys(compartment_id=compartment_id)            
    except Exception as e:
        logging.getLogger().info(f"[Error]list_keys - An error occurred: {e}")
    return list_keys_response

def schedule_secret_deletion(dst_vaults_client, secret_id, deletion_time):    
    result_date = datetime.now() + timedelta(days=44) #Since secret info on pending delete secret cannot be retireved, set default delete to 44 days
    logging.getLogger().info(f"[Info]Deleting a secret {secret_id} and delete date is set to {result_date}")
    schedule_secret_deletion_response = dst_vaults_client.schedule_secret_deletion(
        secret_id=secret_id,
        schedule_secret_deletion_details=oci.vault.models.ScheduleSecretDeletionDetails(
            time_of_deletion=result_date))
    return schedule_secret_deletion    

def cancel_secret_deletion(dst_vaults_client, secret_id):
    cancel_secret_deletion_response = dst_vaults_client.cancel_secret_deletion(
    secret_id=secret_id)
    return cancel_secret_deletion_response.headers

def schedule_secret_deletion(dst_secrets_client,dst_vaults_client, secret_id, deletion_time):
    print("Deleting a secret")
    #Get secret info to get time of deletion
    dst_secret_info=get_secret(dst_secrets_client,dst_vaults_client,secret_id=secret_id)
    schedule_secret_deletion_response = dst_vaults_client.schedule_secret_deletion(
        secret_id=secret_id,
        schedule_secret_deletion_details=oci.vault.models.ScheduleSecretDeletionDetails(
            time_of_deletion=deletion_time))

def cance_secret_deletion(dst_vaults_client, secret_id):
    cancel_secret_deletion_response = dst_vaults_client.cancel_secret_deletion(
    secret_id=secret_id)
    return cancel_secret_deletion_response.headers

def handler(ctx, data: io.BytesIO=None):
    try:
        
        #Limit functions logs
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        # Parse Connector Hub response and get the key information
        logs = json.loads(data.getvalue())
        compartment_id,src_event_name,src_secret_id,freeform_Tags,src_secret_name = extract_info_from_logs(logs)
        logging.getLogger().info(f"[INFO] Variables from Connector Hub - Compartment is {compartment_id}, event name is {src_event_name},secret_id is {src_secret_id},freeform_Tags is {freeform_Tags},secret_name is {src_secret_name} ")
        # Create OCI signer using resource principals
        signer = oci.auth.signers.get_resource_principals_signer()
        """
        Set defaults and hard code values as needed. For advanced users, store the data in function config file and dynamically pull them
        """
        dst_key_name = 'secret-replication-key'
        dest_vault_endpoint = "https://kms.ca-toronto-1.oraclecloud.com"  #https://docs.oracle.com/en-us/iaas/api/#/en/key/release/
        dest_vault_secret_endpoint = "https://vaults.ca-toronto-1.oci.oraclecloud.com" #https://docs.oracle.com/en-us/iaas/api/#/en/secretmgmt/20180608/
        dest_vault_secret_retrieval_endpoint="https://secrets.vaults.ca-toronto-1.oci.oraclecloud.com" #https://docs.oracle.com/en-us/iaas/api/#/en/secretretrieval/20190301/
        dst_secrets_client = oci.secrets.SecretsClient(config={},signer=signer,service_endpoint=dest_vault_secret_retrieval_endpoint)
        src_secrets_client = oci.secrets.SecretsClient(config={},signer=signer)
        src_kms_vault_client = oci.key_management.KmsVaultClient(config={},signer=signer)
        src_kms_vault_client_composite = oci.key_management.KmsVaultClientCompositeOperations(src_kms_vault_client)
        dst_kms_vault_client = oci.key_management.KmsVaultClient(config={},signer=signer, service_endpoint=dest_vault_endpoint)
        dst_kms_vault_client_composite = oci.key_management.KmsVaultClientCompositeOperations(dst_kms_vault_client)
        src_vault_client = oci.vault.VaultsClient(config={},signer=signer)
        dst_vaults_client = oci.vault.VaultsClient(config={},signer=signer, service_endpoint=dest_vault_secret_endpoint)
        dst_vaults_management_client_composite = oci.vault.VaultsClientCompositeOperations(dst_vaults_client)


        #get source vault and secret info
        src_secret_info=get_secret(src_secrets_client,src_vault_client,secret_id=src_secret_id)
        src_vault_info=get_vault(src_kms_vault_client, vault_id=src_secret_info["vault_id"])
        logging.getLogger().info(f"[INFO] Source Secret id is {src_secret_id} and Vault ID is {src_secret_info['vault_id']} ")

        #validate destination vault info
        dest_vault_name = "Backup-" + src_vault_info.data.display_name + "-" + src_vault_info.data.id.split('.')[-3]
        dst_vault_info=list_vault(dst_kms_vault_client, compartment_id=compartment_id,vault_name=dest_vault_name)
        logging.getLogger().info(f"[INFO] Destination vault info {dst_vault_info}")

        #If vault exists
        if dst_vault_info:    
            dst_vault_id=dst_vault_info["vault_id"]
            dst_vault_management_endpoint=dst_vault_info["management_endpoint"]
            logging.getLogger().info(f"[INFO] Dest Vault ID {dst_vault_id}")
            #create/validate KMS key only for Create or Update secret operations. For all other, we dont need this info
            if src_event_name == 'CreateSecret' or src_event_name == 'UpdateSecret':
                # Step 2.1: Validating KMS key in the destination to avoid duplicates 
                # you will need key id only for creating or updating secrets               
                dst_vault_management_client = oci.key_management.KmsManagementClient(config={},signer=signer, service_endpoint=dst_vault_management_endpoint)
                dst_list_keys=list_keys(dst_vault_management_client,compartment_id)
                key_flag=False
                for key_dtls in dst_list_keys.data:                        
                    if key_dtls.display_name == dst_key_name and key_dtls.lifecycle_state == 'ENABLED':
                        dst_key_id=key_dtls.id
                        key_flag=True # KMS Key with same name exists. No need to create new one
                        logging.getLogger().info(f"[INFO] KMS Key {dst_key_id} with same name exists. No need to create new one")
                        break     
                if  key_flag == False:
                    # Step 2.1: Creating KMS key in the destination                
                    dst_vault_management_client = oci.key_management.KmsManagementClient(config={},signer=signer, service_endpoint=dst_vault_management_endpoint)
                    dst_vault_management_client_composite = oci.key_management.KmsManagementClientCompositeOperations(dst_vault_management_client)
                    key = create_key(dst_vault_management_client_composite, dst_key_name, compartment_id).data
                    dst_key_id = key.id
                    logging.getLogger().info(f"[INFO] KMS Key {dst_key_id} doesnt exist, Created new key")

            #For existing vaults, ensure there are no duplicate secrets
            dst_secret_presence=False
            resp_get_secret_by_name = get_secret_by_name(compartment_id, dst_vaults_client,src_secret_info["secret_name"], dst_vault_id, dst_secrets_client)
            if resp_get_secret_by_name:
                dst_secret_presence=True # secret with same name exists in destination vault
                dst_secret_id=resp_get_secret_by_name["secret_ocid"]
                logging.getLogger().info(f"[INFO] Secret {resp_get_secret_by_name['secret_name']} exists in destination and OCID is {dst_secret_id}")
 
            if dst_secret_presence == False and (src_event_name == 'CreateSecret' or src_event_name == 'UpdateSecret'):
                create_secret_key = create_secret(dst_vaults_management_client_composite, compartment_id, dst_vault_id, dst_key_id, src_secret_info).data
                logging.getLogger().info(f"[INFO] Created Secret {create_secret_key.secret_name}")
            elif dst_secret_presence == True and (src_event_name == 'CreateSecret' or src_event_name == 'UpdateSecret'):
                logging.getLogger().info(f"[Warning]  Secret {src_secret_info['secret_name']} already present in dest vault. Updating the secret {resp_get_secret_by_name['secret_name']}")
                update_secret_key_response = update_secret(dst_vaults_management_client_composite,src_secret_info,dst_secret_id)         
            elif src_event_name == 'CancelSecretDeletion':
                cance_secret_deletion(dst_vaults_client, dst_secret_id)
                logging.getLogger().info(f"[Info] CancelSecretDeletion operation executed on {resp_get_secret_by_name['secret_name']}")
            elif src_event_name == 'ScheduleSecretDeletion':
                schedule_secret_deletion(dst_secrets_client,dst_vaults_client, dst_secret_id, resp_get_secret_by_name['time_of_deletion'])
                logging.getLogger().info(f"[Info] ScheduleSecretDeletion operation executed on {resp_get_secret_by_name['secret_name']} and time of delettion is {resp_get_secret_by_name['time_of_deletion']}")                
            else:
                #handle any other state(if there is one) here
                logging.getLogger().info(f"[Info] This code works only for create,update and cancelScheduleDelete events.All other Events will be discarded")
        else:
            logging.getLogger().info(f"[Info] Vault dest_vault_name doest exist in destination region. New Vault will be created")
            if src_event_name == 'CreateSecret' or src_event_name == 'UpdateSecret':
                #destination vault is missing and only allowed operations are Create Secret and Update secret    
                dst_new_vault_info=create_vault(compartment_id=compartment_id, vault_info=src_vault_info, kms_vault_client_composite=dst_kms_vault_client_composite).data
                dst_vault_id=dst_new_vault_info.id
                vault_exists = False
                logging.getLogger().info(f"[Info] Created Vault {dst_new_vault_info.display_name} in Dest region")
                dest_vault_create=True
                dst_vault_id=dst_new_vault_info.id
                dst_vault_management_endpoint=dst_new_vault_info.management_endpoint
                # Step 2.1: Creating KMS key in the destination                
                dst_vault_management_client = oci.key_management.KmsManagementClient(config={},signer=signer, service_endpoint=dst_vault_management_endpoint)
                dst_vault_management_client_composite = oci.key_management.KmsManagementClientCompositeOperations(dst_vault_management_client)
                key = create_key(dst_vault_management_client_composite, dst_key_name, compartment_id).data
                dst_key_id = key.id
                # since its a new vault, no secrets will be present. Create the secret irrespective of its source state.
                create_secret_key_response = create_secret(dst_vaults_management_client_composite, compartment_id, dst_vault_id, dst_key_id, src_secret_info).data
            else:
                logging.getLogger().info(f"[Error] Vault doesnt exist in the destination region and secret deletion or Cancel Secret deletion will be ignored")
    except (Exception, ValueError) as ex:
        logging.getLogger().error(f"[Error] An error occurred: {ex}", exc_info=True)
        return                

