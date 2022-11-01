#!/usr/bin/env bash
bypass=0
usage () {
    echo "USAGE: $0 -r eu-west-1 -p shieldfc_demo -cit m5.2xlarge -eit i3.xlarge.elasticsearch -rit db.t3.xlarge -b"
    echo "  [-r|--aws-region region_name] Customer's AWS region."
    echo "  [-p|--aws-profile-name] Local AWS Profile name"
    echo "  [-cit|--eks-instance-type] Main EKS nodegroup instance type (Default: t3.2xlarge)"
    echo "  [-eit|--elastic-instance-type] Elasticserach data nodes instance type (Default: i3.large.elasticsearch)"
    echo "  [-rit|--rds-instance-type] RDS instance type (Default: db.t3.large)"
    echo "  [-b|--bypass] Bypass manual inputs"
    echo "  [-h|--help] Usage message"
}

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -r|--aws-region)
        REGION="$2"
        shift
        shift
        ;;
        -p|--aws-profile-name)
        PROFILE_NAME="$2"
        shift
        shift
        ;;
        -cit|--main-eks-instance-type)
        main_nodegroup_instance_type="$2"
        shift
        shift
        ;;
        -eit|--elastic-instance-type)
        es_instance_type="$2"
        shift
        shift
        ;;
        -rit|--rds-instance-type)
        rds_instance_type="$2"
        shift
        shift
        ;;
        -b|--bypass)
        bypass=1
        shift
        ;;
        -h|--help)
        help=1
        shift
        ;;
        *)
        usage
        exit 1
        ;;
    esac
done

if [[ -z $REGION ]]; then
    usage
    exit 1
fi

if [[ -z $PROFILE_NAME ]]; then
    usage
    exit 1
fi

export AWS_PROFILE=$PROFILE_NAME
export ENV_NAME=$(aws ssm get-parameter --region $REGION --name "/aft/account_custom_fields/environment_name" --query "Parameter.Value" --output text | jq --raw-output)
export TG_TF_REGISTRY_TOKEN=$(aws ssm get-parameter --region $REGION --name /aft/$ENV_NAME/terraform/registry/token  --query "Parameter.Value" --output text --with-decrypt)
export TF_TOKEN_app_terraform_io=$TG_TF_REGISTRY_TOKEN
if [[ -z $main_nodegroup_instance_type ]]; then
    main_nodegroup_instance_type=$(sed -n -e '/main_nodegroup_instance_type/p' $ENV_NAME/env.hcl | awk '{print $3}')
    echo "==========================IMPORTANT================================"
    echo "Main EKS instance type parameter is not provided, used value from env.hcl ($main_nodegroup_instance_type)."
    echo "You can use --eks-instance-type argument to pass custom EKS main node group instance type."
else
    sed -i -e '/main_nodegroup_instance_type =/ s/= .*/= "'"$main_nodegroup_instance_type"'"/' $ENV_NAME/env.hcl
    git add $ENV_NAME/env.hcl 
    echo "==========================IMPORTANT================================"
    echo "Used EKS main nodegroup instance type: $main_nodegroup_instance_type"
fi

if [[ -z $es_instance_type ]]; then
    es_instance_type=$(sed -n -e '/es_instance_type/p' $ENV_NAME/env.hcl | awk '{print $3}')
    echo "Elasticsearch instance type parameter is not provided, used value from env.hcl ($es_instance_type)."
    echo "You can use --elastic-instance-type argument to pass custom data node instance type."
else
    sed -i -e '/es_instance_type =/ s/= .*/= "'"$es_instance_type"'"/' $ENV_NAME/env.hcl
    git add $ENV_NAME/env.hcl
    echo "Used Elasticsearch data nodes instance type: $es_instance_type"
fi

if [[ -z $rds_instance_type ]]; then
    rds_instance_type=$(sed -n -e '/rds_instance_type/p' $ENV_NAME/env.hcl | awk '{print $3}')
    echo "RDS instance type parameter is not provided, used value from env.hcl ($rds_instance_type)."
    echo "You can use --rds-instance-type argument to pass custom RDS instance type."
else
    sed -i -e '/rds_instance_type =/ s/= .*/= "'"$rds_instance_type"'"/' $ENV_NAME/env.hcl
    echo "Used RDS instance type: $rds_instance_type"
    git add $ENV_NAME/env.hcl
    rm $ENV_NAME/env.hcl-e
    git commit -a -m "[automation]updated env.hcl with new values"
fi

if [[ $help ]]; then
    usage
    exit 0
fi

if [[ $bypass == 1 ]]; then
  echo "Look like you bypassing the manual inputs. Please remove --bypass/-b flag if this is your first run."
  read -p "Proceed NOW!!! (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
fi

if [[ $bypass == 0 ]]; then
  echo "Do you connected to network-account client vpn?"
  read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
else
  echo "================================================================="
  echo "Skipping manual input. Remove --bypass/-b flag for manual inputs."
  echo "Assuming that you are connected to the network-account VPN"
fi

aws sts get-caller-identity > /dev/null 2>&1
RETURN=$?
if [[ $RETURN==0 ]]; then
  ACCOUNT_ID=$(aws sts get-caller-identity | jq  --raw-output ".Account" )
else
  exit 1 && echo "error in authorization with AWS"
fi

if [[ $bypass == 0 ]]; then
  echo "Is the account ID is: $ACCOUNT_ID"
  read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
else
  echo "================================================================="
  echo "Assuming that customer's account is: $ACCOUNT_ID"
fi

REGION=$(aws ssm get-parameter --region $REGION --name "/aft/account_custom_fields/main_region" --query "Parameter.Value" --output text | jq --raw-output) && echo "region is: "$REGION

if [[ $bypass == 0 ]]; then
  echo "The main region recorded in parameter store is: $REGION"
  read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
else
  echo "================================================================="
  echo "The main region recorded in parameter store is: $REGION"
fi

if [[ $bypass == 0 ]]; then
  echo "enviorment name is: "$ENV_NAME
  read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
else
  echo "================================================================="
  echo "The envrironment name stored in paramter store is: "$ENV_NAME
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd parameters
terragrunt apply && echo "===========================applied parameters===========================" && EXIT=0
if [ $EXIT == 1 ]; then
  echo "parameters failed"
  exit 1
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd eks
terragrunt apply && echo "===========================applied eks===========================" && EXIT=0
if [ $EXIT == 1  ]; then 
  echo "eks failed"
  exit 1
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd eks-argocd
terragrunt apply && echo "===========================applied eks-argocd===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "eks-argocd failed"
  exit 1
fi

# this script creating ssh-key pair if not exists in parameter store go given user
# injecting it to parameter store of exists localy only or not exists at all
# injecting a private key secret to k8s cluster

if [[ $bypass == 0 ]]; then
  read -p "Secret injection phase,Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
else
  echo "================================================================="
  echo "Secret injection phase started"
fi

CUSTOMER_NAME=$(aws ssm get-parameter --region $REGION --name "/aft/account_custom_fields/customer_name" --query "Parameter.Value" --output text | jq --raw-output)

if [[ $bypass == 0 ]]; then
  echo "customer name is: "$CUSTOMER_NAME
  read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
else
  echo "================================================================="
  echo "Assuming that correct customer name is: "$CUSTOMER_NAME
fi

aws eks update-kubeconfig --name "$CUSTOMER_NAME-$ENV_NAME" --region "$REGION"
RETURN=$?
if [[ RETURN==0 ]]; then
  echo "succfuly configured eks kubectconfig"
else 
  echo "error in eks kubeconfig"
  exit 1
fi

#kubectl set context
kubectl config use-context arn:aws:eks:$REGION:"$ACCOUNT_ID":cluster/$CUSTOMER_NAME-$ENV_NAME

if [[ $(kubectl describe secrets/ops-ssh-keys) ]]; then
  echo "secret alredy exists in k8s cluster"
else
  #check if private key exists in ssm parameter store
  PRIVATE_KEY=$(aws ssm get-parameter --region $REGION --name "/aft/bitbucket/ssh_private_key" --query "Parameter.Value" --output text --with-decrypt)
  if [[ $PRIVATE_KEY ]]; then
    echo "private key exists in parameter store, injecting the secret"
    kubectl create secret generic ops-ssh-keys --from-literal=ops-secret-key="$PRIVATE_KEY"
  else
    echo "ssh key doesn't exists in parameter store, creating it localy"
    PREFIX_PATH=~
    if [[ -f "$PREFIX_PATH/.ssh/$CUSTOMER_NAME/$CUSTOMER_NAME-$ENV_NAME-ops" ]]; then 
      echo "ssh key-pair alredy exists localy"
    else
      mkdir -p ~/.ssh/$CUSTOMER_NAME
      echo "creating ssh key pair in ~/.ssh/$CUSTOMER_NAME/$CUSTOMER_NAME-$ENV_NAME-ops"
      ssh-keygen \
      -q \
      -t rsa \
      -N ''\
      -f ~/.ssh/$CUSTOMER_NAME/$CUSTOMER_NAME-$ENV_NAME-ops && echo "have create ssh-key pair in $PREFIX_PATH/.ssh/$CUSTOMER_NAME/$CUSTOMER_NAME-$ENV_NAME-ops"
    fi
    echo "uploading new ssh key-pair to parametersore"
    KEY_ID=$(aws ssm get-parameter --region $REGION --name /aft/$ENV_NAME/kms/key_id | jq --raw-output ".Parameter.Value")
    aws ssm put-parameter --name "/aft/bitbucket/ssh_private_key" --value "$(cat $PREFIX_PATH/.ssh/$CUSTOMER_NAME/$CUSTOMER_NAME-$ENV_NAME-ops)" --type "SecureString" --key-id "$KEY_ID" --overwrite > /dev/null && echo "succefuly uploaded private key to parameter store" || echo "failed upload private key to parameter store"
    aws ssm put-parameter --name "/aft/bitbucket/ssh_public_key" --value "$(cat $PREFIX_PATH/.ssh/$CUSTOMER_NAME/$CUSTOMER_NAME-$ENV_NAME-ops.pub)" --type "SecureString" --key-id "$KEY_ID" --overwrite > /dev/null && echo "succefuly uploaded public key to parameter store" || echo "failed upload private key to parameter store"
    echo "injection of secret to k8s cluster"
    kubectl create secret generic ops-ssh-keys --from-file=ops-secret-key=$PREFIX_PATH/.ssh/$CUSTOMER_NAME/$CUSTOMER_NAME-$ENV_NAME-ops && echo "sucessfuly injected private ssh-key secret to k8s"
  fi
fi


aws ssm get-parameter --region $REGION --name "/aft/bitbucket/ssh_public_key" --query "Parameter.Value" --output text --with-decryption | pbcopy
if [[ $bypass == 0 ]]; then
  echo "please paste the public key (ALREADY IN YOURs CLIPBOARD) to bitbucket repository"
  read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
else
  echo "================================================================="
  echo "Assuming that you already added the public key to the bitbucket repository"
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd vault
terragrunt apply && echo "===========================applied vault===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "vault failed"
  exit 1
fi

#Dont destory before helm-rls destroying done
EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd waf
terragrunt apply && echo "===========================applied waf===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "waf failed"
  exit 1
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd helm-rls
terragrunt apply && echo "===========================helm-rls vault===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "helm-rls failed"
  exit 1
fi


echo "=====================Init phase 2 - vault automation======================="
PRIVATE_DOMAIN_NAME=$(aws ssm get-parameter --region $REGION --name "/aft/private_dns/domain_name" --query "Parameter.Value" --output text) && echo "private domain name is: "$PRIVATE_DOMAIN_NAME
VAULT_ADDR="https://vault.$PRIVATE_DOMAIN_NAME"
EST=600
while curl --head --silent --fail $VAULT_ADDR; [ "$?" -eq 6 ]; do sleep 5; echo "waiting connection to $VAULT_ADDR"; echo "estimated time is $EST seconds"; EST=$(( $EST-5 )); done

while [[ "$(kubectl -n vault get pods | awk '{print $3}' | tail -n 3 | head -n 1)" -ne "Running" ]]; do sleep 5; echo "waiting for vault-0 pod to run"; done

KEY_ID=$(aws ssm get-parameter --region $REGION --name /aft/$ENV_NAME/kms/key_id | jq --raw-output ".Parameter.Value")

#init vault and extract tookens
VAULT_INIT=$(kubectl exec -i -t -n vault vault-0 -c vault "--" sh -c "vault operator init -format "json"") 
if [ $? == 0 ]; then
  echo "succefuly init vault"
  #parse and upload to parameter store
  for i in {0..4}; do
  aws ssm put-parameter\
    --region $REGION \
    --name "/aft/$ENV_NAME/vault/recovery_keys_b64_$i"\
    --value "$(echo $VAULT_INIT | jq --raw-output ".recovery_keys_b64[$i]")"\
    --type "SecureString"\
    --key-id "$KEY_ID"\
    --overwrite\
    > /dev/null \
    && echo "successfully uploaded recovery key $i to parameter store" \
    || echo "failed upload recovery key $i to parameter store"
  done
  aws ssm put-parameter\
    --region $REGION \
    --name "/aft/$ENV_NAME/vault/root_token"\
    --value "$(echo $VAULT_INIT | jq --raw-output ".root_token")"\
    --type "SecureString"\
    --key-id "$KEY_ID"\
    --overwrite\
    > /dev/null \
    && echo "successfully uploaded root token to parameter store" \
    || echo "failed upload private key to parameter store"

else
  echo "init already have done"
fi

export VAULT_TOKEN=$(aws ssm get-parameter --region $REGION --name "/aft/$ENV_NAME/vault/root_token" --query "Parameter.Value" --output text --with-decrypt ) && echo "sucessfuly got root token from parameter store" || echo "failed get root token from parameter store"
sleep 5
kubectl exec -i -t -n vault vault-0 -c vault "--" sh -c "echo $VAULT_TOKEN | xargs vault login" > /dev/null 2>&1 \
&& echo "suceffuly login to pod vault-0 with root token" \
|| echo "error in login to pod vault-0 with root toekn"
kubectl exec -i -t -n vault vault-0 -c vault "--" sh -c "vault auth enable kubernetes" \
&& echo "suceffuly enabled kubernetes auth" \
|| echo "unsuceffuly enabled kubernetes auth"


CMD=$(cat <<EOF
vault write auth/kubernetes/config \
token_reviewer_jwt="\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
kubernetes_host=https://\${KUBERNETES_PORT_443_TCP_ADDR}:443 \
kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly written to auth/kubernetes/config" \
|| echo "unsuceffuly written to auth/kubernetes/config"

#Policy
CMD=$(cat <<EOF
  cat <<EOF > /tmp/policy.hcl
  path "kvv1/*" {
    capabilities = ["read"]
  }

  path "kvv2/data/*" {
    capabilities = ["read"]
  }
  
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly created policy file /tmp/policy.hcl" \
|| echo "unsuceffuly created policy file /tmp/policy.hcl"

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault policy write vault-secrets-operator /tmp/policy.hcl" \
&& echo "suceffuly written policy vault-secrets-operator" \
|| echo "unsuceffuly written tovault-secrets-operator"


CMD=$(cat <<EOF
vault write auth/kubernetes/role/vault-secrets-operator \
bound_service_account_names="vault-secrets-operator" \
bound_service_account_namespaces="vault" \
policies=vault-secrets-operator \
ttl=24h
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly written to auth/kubernetes/role/vault-secrets-operator" \
|| echo "unsuceffuly written to auth/kubernetes/role/vault-secrets-operator"

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault secrets enable -path=kvv1 -version=1 kv" \
&& echo "suceffuly enabled secret kvv1" \
|| echo "unsuceffuly enabled secret kvv1"

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault secrets enable -path=kvv2 -version=2 kv" \
&& echo "suceffuly enabled secret kvv2" \
|| echo "unsuceffuly enabled secret kvv2"


kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault secrets enable transit" \
&& echo "suceffuly enabled secret transit" \
|| echo "unsuceffuly enabled secret transit"

#####app-orders#######
#policy
CMD=$(cat <<EOF
  cat <<EOF > /tmp/policy2.hcl
    path "transit/encrypt/orders" {
      capabilities = [ "update" ]
    }
    path "transit/decrypt/orders" {
      capabilities = [ "update" ]
    }
  
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly created policy file /tmp/policy2.hcl" \
|| echo "unsuceffuly created policy file /tmp/policy2.hcl"

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault policy write app-orders /tmp/policy2.hcl" \
&& echo "suceffuly written policy app-orders" \
|| echo "unsuceffuly written to app-orders"


CMD=$(cat <<EOF
vault write auth/kubernetes/role/app-orders \
bound_service_account_names="aws-archive,migration-validator,migration-logging,search-api,transcriber-aws,backend,queue-separator,archive,eml-sender,models-api,models-config,monitor,orch-api,policy,python-tools,scheduler,encrypt-decrypt,transcription-replanner,voice-converter,voice-data-fetcher,smtp-sender,worker-batch,worker-continuous,worker-exec,rnd-delivery-tools,encrypt-decrypt,retention-delete,tgm-executor-api,smtp-server,widgets-reports,worker-reports,relationship-map-10am,relationship-map-4am,relationship-map-6pm,shield-index-minimizer" \
bound_service_account_namespaces="$ENV_NAME" \
policies=app-orders \
ttl=24h
EOF
)
kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly written to auth/kubernetes/role/app-orders" \
|| echo "unsuceffuly written to auth/kubernetes/role/app-orders"

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault write -f transit/keys/orders" \
&& echo "suceffuly written policy app-orders" \
|| echo "unsuceffuly written to app-orders"

# Kafka
CMD=$(cat <<EOF
  cat <<EOF > /tmp/policy3.hcl
    path "kvv2/data/kafka" {
      capabilities = ["read"]
}
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly created policy file /tmp/policy3.hcl" \
|| echo "unsuceffuly created policy file /tmp/policy3.hcl"

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault policy write kafka-policy /tmp/policy3.hcl" \
&& echo "suceffuly written policy kafka-policy" \
|| echo "unsuceffuly written to kafka-policy"


CMD=$(cat <<EOF
vault write auth/kubernetes/role/kafka-role \
bound_service_account_names="aws-archive,migration-validator,migration-logging,search-api,transcriber-aws,backend,queue-separator,archive,eml-sender,models-api,models-config,monitor,orch-api,policy,python-tools,scheduler,encrypt-decrypt,transcription-replanner,voice-converter,voice-data-fetcher,smtp-sender,worker-batch,worker-continuous,worker-exec,rnd-delivery-tools,encrypt-decrypt,retention-delete,tgm-executor-api,smtp-server,widgets-reports,worker-reports,relationship-map-10am,relationship-map-4am,relationship-map-6pm,shield-index-minimizer" \
bound_service_account_namespaces="$ENV_NAME" \
policies=kafka-policy \
ttl=24h
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly written to auth/kubernetes/role/kafka-role" \
|| echo "unsuceffuly written to auth/kubernetes/role/kafka-role"

CMD=$(cat <<EOF
vault write auth/kubernetes/role/key-value-role \
bound_service_account_names="aws-archive,migration-validator,migration-logging,search-api,transcriber-aws,backend,queue-separator,archive,eml-sender,models-api,models-config,monitor,orch-api,policy,python-tools,scheduler,encrypt-decrypt,transcription-replanner,voice-converter,voice-data-fetcher,smtp-sender,worker-batch,worker-continuous,worker-exec,rnd-delivery-tools,encrypt-decrypt,retention-delete,tgm-executor-api,smtp-server,widgets-reports,worker-reports,relationship-map-10am,relationship-map-4am,relationship-map-6pm,shield-index-minimizer" \
bound_service_account_namespaces="$ENV_NAME" \
policies=vault-secrets-operator \
ttl=24h
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly written to auth/kubernetes/role/key-value-role" \
|| echo "unsuceffuly written to auth/kubernetes/role/key-value-role"

#####snapshot#######
CMD=$(cat <<EOF
  cat <<EOF > /tmp/policy-snapshot.hcl 
    path "sys/storage/raft/snapshot" {
      capabilities = ["create","read"]
    }
EOF
)

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly created policy file /tmp/policy-snapshot.hcl" \
|| echo "unsuceffuly created policy file /tmp/policy-snapshot.hcl"

kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "vault policy write snapshot /tmp/policy-snapshot.hcl" \
&& echo "suceffuly written policy snapshot" \
|| echo "unsuceffuly written to snapshot"

CMD=$(cat <<EOF
vault write auth/kubernetes/role/snapshot \
bound_service_account_names="vault-snapshots" \
bound_service_account_namespaces="vault" \
policies=snapshot \
ttl=30m
EOF
)
kubectl exec -i -t -n vault vault-0 -c vault "--" sh \
-c "$CMD" \
&& echo "suceffuly written to auth/kubernetes/role/snapshot" \
|| echo "unsuceffuly written to auth/kubernetes/role/snapshot"

kubectl exec vault-1 -n vault \
-- vault operator raft join http://vault-0.vault-internal:8200 \
&& echo "suceffuly joined vault-1 to raft" \
|| echo "unsuceffuly joined vault-1 to raft"

kubectl exec vault-2 -n vault \
-- vault operator raft join http://vault-0.vault-internal:8200 \
&& echo "suceffuly joined vault-2 to raft" \
|| echo "unsuceffuly joined vault-2 to raft"


#vault secrets
EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd vault-secrets
terragrunt apply && echo "===========================vault-secrets===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "vault-secrets failed"
  exit 1
fi

export ARGOCD_AUTH_USERNAME=admin 
export ARGOCD_AUTH_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d && echo)

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd argocd-init
terragrunt apply && echo "===========================argocd-init===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "argocd-init failed"
  exit 1
fi

EXIT=1 
cd $SCRIPT_DIR/$ENV_NAME
cd elasticsearch
terragrunt apply && echo "===========================elasticsearch===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "elasticsearch failed"
  exit 1
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd mysql-rds
terragrunt apply && echo "===========================applied mysql-rds===========================" && EXIT=0
if [ $EXIT == 1  ]; then 
  echo "mysql-rds failed"
  exit 1
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd s3-archive
terragrunt run-all apply --terragrunt-ignore-external-dependencies && echo "===========================s3-archives===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "s3-archives failed"
  exit 1
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd s3-vault-snapshots
terragrunt apply && echo "===========================s3-vault-snapshots===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "s3-vault-snapshots failed"
  exit 1
fi

EXIT=1
cd $SCRIPT_DIR/$ENV_NAME
cd eks-sa-vault
terragrunt apply && echo "===========================eks-sa-vault===========================" && EXIT=0
if [ $EXIT == 1 ]; then 
  echo "eks-sa-vault failed"
  exit 1
fi