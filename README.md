# Nitro Enclave + KMS lock out

## Overview

This project demonstrates a powerful security paradigm: enabling a specific enclave to exclusively possess decryption capabilities using a designated KMS (Key Management Service) key. The key aspect of this demonstration is the intentional exclusion of root user access to the decryption process.

### Key Objectives

Exclusive Decryption by Enclave: Illustrate how an enclave can be the only entity capable of decrypting a secret, leveraging a specified KMS key.
Root User Restriction: Showcase the process of restricting even the root user from accessing the decrypted content, thereby enhancing the security model.

### End Goal

The culmination of this demo is a practical and compelling demonstration where the enclave successfully decrypts a secret using the KMS key. This process uniquely occurs without granting decryption capabilities to the root user, thereby emphasizing the enclave's exclusive access and operation.

As an insightful exploration into advanced security mechanisms, the demo showcases how controlled access to encrypted data can be effectively implemented in a cloud environment.

## Tutorial steps
### (1) Launch EC2 instance
The EC2 instance can be launched by preferred choice of 2 options: CLI or AWS Console. \
\
Launching via CLI

```
aws ec2 run-instances \
--image-id ami-0759f51a90924c166 \
--count 1 \
--instance-type m5.xlarge \
--key-name "WSLDESKTOPWIN" \
--subnet-id subnet-05064f5ebf36a6796 \
--associate-public-ip-address \
--enclave-options 'Enabled=true'
```

Launching via AWS Console
  - On AWS dashboard, navigate to service: EC2
  - Click on "Launch instance"
  - Provide a name for the instance
  - Amazon linux 2023 AMI should be auto-selected, if not please select
  - Architecture 64-bit (x86) should be auto-selected, if not please select
  - For instance type, click to open up drop-down, search for m5.xlarge and select
  - At key-pair login, create a new key-pair
  - Under network settings, "Create a new security group" should be auto-selected if not please select
  - Under network settings, "Allow SSH from" should be auto-selected, if not please select, change "Anywhere" to "My IP" \
    (Changing "Anywhere" to "MyIP" here satisfies the step (2) which produces the same changes)
  - Click on "Advanced settings" to open up the section, scroll down to "Nitro Enclave" and select "Enable"
  - Click on "Launch instance"

### (2) Edit security group rules to allow SSH

For SSH access to our newly launched ec2 instance, an inbound rule must be added to the corresponding security group. \
_Note:This step can be skipped if ec2 was launched via AWS console and SSH access was set to "MyIP" under Network settings_
- On AWS dashboard, Navigate to service: EC2
- Click on "instances" in the side-bar on the left
- Click to select the previously launched instance, click on "Security" tab on the panel below
- Under "Security groups" label, click on the security group link (e.g sg-a1b2c3...)
- Click on "Edit Inbound rules" on the panel below
If there are no rules:
- Click on "Add rule", select "SSH" for Type, select "My IP" for Source and save
If there is a rule:
- Update Type to "SSH", Source to "My IP" and save

### (3) Transfer app files to ec2 instance
Note: Steps below are to be performed on local machine.

 - Download app files in local machine
```
git clone git@gitlab.com:cryptnox-issuer/nitro-enclace-kms-lock-out.git
```
 - Send app files to ec2 instance
```
scp -r ./nitro-enclace-kms-lock-out/ ec2-user@34.228.63.154:~
```

### (4) Setup EC2 instance

 - Connect to ec2 instance via SSH 
```
ssh -A ec2-user@34.228.63.154
```
 - Install dependencies
```
sudo yum install git docker aws-nitro-enclaves-cli-devel aws-nitro-enclaves-cli gcc pip python3-devel -y
```
 - Add user permissions
```
sudo usermod -aG ne ec2-user
sudo usermod -aG docker ec2-user
```
 - Enable services
```
sudo systemctl enable --now docker
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now nitro-enclaves-vsock-proxy.service
```
 - (Optional) Enable agent-forwarding
```
sudo nano /etc/ssh/sshd_config
```
 - Reboot for changes to take effect
```
sudo reboot
```
### (5) Setup app requirements
 - Create python virutal environment & activate
```
python3 -m venv venv
source venv/bin/activate
```
 - Navigate to "enclave" directory and install dependencies
```
cd ./nitro-enclace-kms-lock-out/enclave
pip install -r enclave/requirements.txt
```
 - Build KMS tool
```
chmod +x ./build_kms_tool.sh
./build_kms_tool.sh
```

### (6) KMS Key and IAM policy creation
 - Create KMS key for encryption & decryption purposes:
     - On AWS dashboard, navigate to service: Key Management Service (KMS)
     - Click on "Customer managed keys" in the side-bar on the left
     - Click on "Create key"
     - "Symmetric" should be auto-selected in key type, if not please select.
     - "Encrypt and Decrypt" should also be auto-selected if not please select, click "Next"
     - Provide an alias for the key (e.g lockout-encdec)
     - Provide description for the key ​(e.g Key used for encryption and decryption of secrets)
     - Select your account in key administrators, Click "Next"
     - Select your account in key usage permissions, Click "Next"​
     - Click "Finish"
 - Create IAM policy to allow encryption & secret fetch
     - On AWS dashboard, navigate to service: IAM
     - Click on "Policies" in the side-bar on the left, and click "Create policy"​
     - Click on "JSON" to switch the policy editor to JSON view
     - Add the following policy
       
       ```
       {
           "Version":"2012-10-17",
           "Statement": [
               {
                   "Sid": "Statement1",
                   "Effect": "Allow",
                   "Action": [
                       "kms:Encrypt",
                       "secretsmanager:CreateSecret",
                       "secretsmanager:GetSecretValue"
                       ],
                   "Resource": [
                       "*"
                       ]
               }
           ]
       }
       ```
     - Click "Next"
     - Provide a policy name (e.g Lockout-kms-policy)
     - Click "Create policy"
  
### (7) Encrypted secret & IAM role creation
 - Create an IAM role with previously created policy
     - On AWS dashboard, navigate to service: IAM
     - Click on "Roles" in the side-bar on the left, then click "Create Role"
     - "AWS Service" selected by default should be selected by default, if not please select
     - Select "EC2" for use case, then click "Next"
     - Search for the previously created policy in step (6) then tick the box, click "Next"
     - Provide role name (e.g Lockout-test-role), click "Create role"
 - Attach the newly created IAM role to the ec2 instance
     - On the AWS dashboard, navigate to service: EC2
     - Click "instances" in the side-bar on the left
     - Select the previously launched ec2 instance
     - Click Actions -> Security -> Modify IAM role
     - Select the preiviously created IAM role, then click "Update IAM role"
 - Create encrypted key via script
     - On ec2 instance, run the file `create_key.py` with KMS ARN & secret name as parameters \
       Format:
        ```
        python create_key.py <kms_arn> <secret_name>
        ```       
       Example:
        ```
        python create_key.py arn:aws:kms:eu-central-1:1234:key/a1b2c2-d4e5f6-abcdef supersecretkey
        ```

### (8) Enclave setup
 - In enclave.py, line 122, replace the secret name with the previously saved secret name and save file
 - Build docker image
```
docker build -t lockout-enclave .
```
 - Build enclave image file (EIF)
```
nitro-cli build-enclave --docker-uri lockout-enclave:latest --output-file lockout.eif
```
 - Update enclave resource allocation
```
sudo nano /etc/nitro-enclaves/allocator.yaml
```
 - Update "memory_mib" to 2560
 - (To exit) press "Ctrl + X", "Y", then "Enter"
 - Restart the service
```
sudo systemctl restart nitro-enclaves-allocator.service
```
 - Run enclave
```
nitro-cli run-enclave --enclave-cid 20 --eif-path ./lockout.eif --cpu-count 2 --memory 2560 --debug-mode false --enclave-name lockout
```
 - (Optional) Confirm enclave is running
```
nitro-cli describe-enclaves
```
### (9) Lock-out root user & limit decryption to enclave
 - Get ARN of IAM role
     - On AWS dashboard, navigate to service: IAM
     - Click on "Roles" in the side-bar on the left
     - Search for the role previously created, Click on the role
     - Copy the value of "ARN"
 - Get Enclave PCR0 value
     - On the ec2 instance terminal, run:
        ```
        nitro-cli describe-enclaves
        ```
     - Copy the corresponding value of the key "PCR0", example output below
       ```
       {
          "Measurements": {
            "HashAlgorithm": "Sha384 { ... }",
            "PCR0": "d425a8dddca64416b9bd2b1a352978198ee2cf2adfea7b899c3b91b441988ce40c867ed6f6234b8de88ec254d40c4bca",
            "PCR1": "52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546",
            "PCR2": "32e5a1eeac8046d3389f2519c7d965f263584b131953b7b3ae54c320194084675bf306a6ef87cc8bccd34549433b396c"
          }
        }
       ```
 - Update KMS policy
     - On AWS dashboard, navgate to service: Key Management Service (KMS)
     - Click on "Customer managed keys" in the side-bar on the left
     - Click "JSON' to switch the policy editor to JSON view
     - Add the following rule in the statement list, fill in the ARN and PCR0 values at respective locations
       ```
       {
           "Sid":"Enable decrypt from enclave",
           "Effect":"Allow",
           "Principal":{
                   "AWS":"<Insert IAM role ARN here>"
           },
           "Action":"kms:Deecrypt",
           "Resource":"*",
           "Condition":{
               "StringEqualsIgnoreCase":{
                   "kms:RecipientAttestation:ImageSha384":"<Insert PCR0 value here>"
               }
           }
       }
       ```
     - Delete JSON block containing permissions for the root user \
       _This locks out the root user_
     - Delete the line "kms:Decrypt" from the JSON block for Key admministrators \
       _This ensures the enclave to be the sole existing resource with decryption capabilities_
  
### (10) Test the setup
Each command to be executed in a seperate terminal shell:
 - Run relay server \
   _This starts the relay server which helps enclave fetch secrets_
```
python relay_server.py
```
 - Run test script \
   _This sends a test transaction to enclave for signing bytes using the secret seed in Secret Manager decrypted by KMS key_
```
python test.py
```
 - Run user decryption test (Expects to output a permissions error) \
   _The permissions error returned hereby confirms that usage of the key from root account is disabled (hence, locked out)_










