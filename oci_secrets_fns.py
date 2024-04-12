import logging
import oci
import sys 
from datetime import datetime, timedelta
class oci_secrets_fns:

    def extract_info_from_logs(self,logs):
        log_entry = logs[0].get("data", {})
        compartment_id = log_entry.get("compartmentId")
        event_name = log_entry.get("eventName")
        secret_id = log_entry.get("resourceId")
        freeform_Tags=log_entry.get("freeformTags")
        secret_name=log_entry.get("source")

        return compartment_id,event_name,secret_id,freeform_Tags,secret_name

    def get_vault(self, kms_vault_client, vault_id):
        vault_list = {}
        try:
            vault_resp = kms_vault_client.get_vault(vault_id=vault_id)
            vault_data = {}
            vault_data["display_name"] = vault_resp.data.display_name
            vault_data["freeform_tags"] = vault_resp.data.freeform_tags
            vault_data["management_endpoint"] = vault_resp.data.management_endpoint
            vault_data["vault_type"] = vault_resp.data.vault_type
            vault_data["vault_id"] = vault_resp.data.id
            vault_data["lifecycle_state"] = vault_resp.data.lifecycle_state
            vault_list[vault_resp.data.display_name] = vault_data
        except Exception as e:
            logging.getLogger().error(f"[Error]get_vault - Error : {e}")

        return vault_resp
    def get_vaults(self,kms_vault_client, compartment_id):
        vault_list = {}
        try:
            vault_resp = kms_vault_client.list_vaults(compartment_id)
            for v in vault_resp.data:
                if v.lifecycle_state == 'ACTIVE':
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
    def list_vault(self, kms_vault_client, compartment_id,vault_name):
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
            logging.getLogger().error(f"[Error]list_vault - {e}")

        return vault_data

    def get_secret (self, secrets_client,vault_client,secret_id):
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
            logging.getLogger().error(f"[Error] Secret {secret_data.data.secret_name} is in {secret_data.data.lifecycle_state} State")
        
        return secrets_info

    def create_vault(self, compartment_id, vault_info, kms_vault_client_composite):  
            if 'data' in vault_info:
                logging.getLogger().info(f"[Info] Vault info {vault_info.data}")
                dest_vault_name = "Backup-" +  + "-" + vault_info.data.id.split('.')[-3]
                dst_vault_type = vault_info.data.vault_type
                dst_freeform_tags=vault_info.data.freeform_tags
            else:
                dest_vault_name = "Backup-" + vault_info["display_name"] + "-" + vault_info["vault_id"].split('.')[-3]
                dst_vault_type=vault_info["vault_type"]
                display_name=dest_vault_name
                dst_freeform_tags=vault_info["freeform_tags"]
            logging.getLogger().info(f"[Info] Creating vault {dest_vault_name} in {compartment_id} compartment")

            vault_details = oci.key_management.models.CreateVaultDetails(
                compartment_id=compartment_id,
                vault_type=dst_vault_type,
                display_name=dest_vault_name,
                freeform_tags=dst_freeform_tags
            )            
            response = kms_vault_client_composite.create_vault_and_wait_for_state(
                vault_details,
                wait_for_states=[oci.key_management.models.Vault.LIFECYCLE_STATE_ACTIVE]
            )
            return response


    def get_secret_by_name(self, compartment_id, vault_client,secret_name, vault_id, secrets_client):
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

    def create_secret(self,vaults_management_client_composite, compartment_id, vault_id, key_id, secret_details):
        try:
            if 'PENDING' in secret_details['secret_stages']:
                logging.getLogger().info(f"[Info]Latest version of Secret {secret_details['secret_name']} is in 'Pending' stage and it will be replicated as Active version")
               
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
            logging.getLogger().error(f"[Error] Creating secret: {secret_details} {e}")
            return None

    def update_secret(self,vaults_management_client_composite,secret_details,secret_id):
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
            logging.getLogger().error(f"[Error]update_secret - {e}")
            return None

    def create_key(self,key_mgmt_composite, dst_key_name, compartment_id):
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
            logging.getLogger().error(f"[Error]create_key - {e}")
            return None

    def list_keys(self, key_management_client,compartment_id):
        list_keys_response = None
        try:
            list_keys_response = key_management_client.list_keys(compartment_id=compartment_id)            
        except Exception as e:
            logging.getLogger().error(f"[Error]list_keys - An error occurred: {e}")
        return list_keys_response

    def schedule_secret_deletion(self,dst_vaults_client, secret_id, deletion_time):  
        result_date = datetime.now() + timedelta(days=44) #set default delete to max 44 days, this will protect from any accidental deletion
        schedule_secret_deletion_response = dst_vaults_client.schedule_secret_deletion(
            secret_id=secret_id,
            schedule_secret_deletion_details=oci.vault.models.ScheduleSecretDeletionDetails(
                time_of_deletion=result_date))
        return schedule_secret_deletion_response    

    def cancel_secret_deletion(self,dst_vaults_client, secret_id):
        cancel_secret_deletion_response = dst_vaults_client.cancel_secret_deletion(
        secret_id=secret_id)
        return cancel_secret_deletion_response.headers


    
    def list_secrets(self, compartment_id, vault_client, src_vault_id, secrets_client):
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