# Nitro Enclace + KMS lock out

# LAUNCH INSTANCE VIA CLI

aws ec2 run-instances \
--image-id ami-0759f51a90924c166 \
--count 1 \
--instance-type m5.xlarge \
--key-name "WSLDESKTOPWIN" \
--subnet-id subnet-05064f5ebf36a6796 \
--associate-public-ip-address \
--enclave-options 'Enabled=true'

# Notes for SSH to instance: you must enable SSH in the inbound rule of the security group of the above instance
# Go to EC2 -> instance -> Security -> Inbound Rules -> Click on the corresponding Security Group
#Edit Inbound Rules and add SSH

ssh -A ec2-user@34.228.63.154

# install dependencies

sudo yum install git docker aws-nitro-enclaves-cli-devel aws-nitro-enclaves-cli gcc pip python3-devel -yy

# configure environment

sudo usermod -aG ne ec2-user
sudo usermod -aG docker ec2-user
sudo systemctl enable --now docker
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now nitro-enclaves-vsock-proxy.service
sudo reboot

#Note: if you want to allow agent forwarding in new instance, enable it in "sudo nano /etc/ssh/sshd_config"


#donwload app on local folder
git clone git@gitlab.com:cryptnox-issuer/nitro-enclace-kms-lock-out.git
#send to remote machine
scp -r ./nitro-enclace-kms-lock-out/ ec2-user@34.228.63.154:~

python3 -m venv venv
source venv/bin/activate

# go into the "enclave" directory:
cd ./nitro-enclace-kms-lock-out/enclave

# Install python requirements
pip install -r enclave/requirements.txt

# Build KMS tool:
chmod +x ./build_kms_tool.sh
./build_kms_tool.sh


# PART X - Perform Key Creation part (see slides)

# in AWS Create the following policy for the key
# Navigate to "IAM" on AWS Dashboard
# Click on "Policies", and "Create policy"
# Click "Next" , then switch to JSON view


{ 
    "Version": "2012-10-17", 
    "Statement": [ 
        { 
            "Sid": "Statement1", 
            "Effect": "Allow", 
            "Action": [ 
                "kms:CreateKey", 
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

# Click next
# Input Policy name: "Lockout-kms-policy" or as desired
# click "Create Policy"

# PART Y - Generate a secret

# etc..etc...



# PART ... Build the enclave

# update line 122 of enclave.py in case name of secret is different

# Build Docker Image

docker build -t lockout-enclave . 

# Convert Docker Image into Enclave Image (EIF file)
 
nitro-cli build-enclave --docker-uri lockout-enclave:latest --output-file lockout.eif

# Note: if you type docker images, you will notice that you have the followings:





# Copy the displayed information below for later
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "d425a8dddca64416b9bd2b1a352978198ee2cf2adfea7b899c3b91b441988ce40c867ed6f6234b8de88ec254d40c4bca",
    "PCR1": "52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546",
    "PCR2": "32e5a1eeac8046d3389f2519c7d965f263584b131953b7b3ae54c320194084675bf306a6ef87cc8bccd34549433b396c"
  }
}


# Update memory_mib to 2560 in:
sudo nano /etc/nitro_enclaves/allocator.yaml

# Restart Allocator Service

sudo systemctl restart nitro-enclaves-allocator.service

# 
nitro-cli run-enclave --config enclave-config.json --eif-path lockout.eif
nitro-cli run-enclave --eif-path lockout.eif --debug-mode

# List again enclave details:
nitro-cli describe-enclaves

# PART ... Update KMS ROLE
# Find previously created role and copy arn (Something like: arn:aws:iam::665309014761:role/lockout-test-role)


# PART... 
# Write down the PCR0 and policy arn
# Fill up the below json file with corresponding values for both

{ 
            "Sid": "Enable decrypt from enclave", 
            "Effect": "Allow", 
            "Principal": { 
                "AWS": "<Insert IAM role ARN here>" 
            }, 
            "Action": "kms:Decrypt", 
            "Resource": "*", 
            "Condition": { 
                "StringEqualsIgnoreCase": { 
                    "kms:RecipientAttestation:ImageSha384": "<Insert the PCR0 Value here>" 
                } 
            } 
}

# Go into KMS, selcted the KMS key used for the projec
# Go into "key Policy", click on:"Switch to Policy View"








