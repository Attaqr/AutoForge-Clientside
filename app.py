import os
import time
from tkinter import *
from tkinter.filedialog import askdirectory
import customtkinter as ctk
import sys
import boto3
from jinja2 import Environment, FileSystemLoader
import glob
import re
import shutil
import jwt
import requests
import json


############################################### Functionality/Backend ######################################################################

# The App class encapsulates the entire GUI application.
class App:
    def __init__(self):
       
        self.languages = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.cpp': 'C++',
            '.hpp': 'C++ Header',
            '.c': 'C',
            '.h': 'C Header',
            '.java': 'Java',
            '.php': 'PHP',
        }
        self.rawToken = {'rawtoken': None}
        self.userId = {'userid': None}
        self.amount = []
        self.guiInput = {'template': None,
                         'os': None,
                         'ram': None}
        self.subnetsInUse = {'cidr1': None,
                             'cidr2': None}
        self.dirs = {'client_path': None,
                     'highest_template': None,
                     'ansible_template': None,
                     'email': None,
                     'code': None,
                     'zip': None,
                     'rds_token': None}
        self.env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blueprints')))
        self.relativePath = os.curdir # The current directory.
        self.ref = self.check_auth()
        self.store_value()
        self.init_gui()
        
# checks language of get_folder(self) method
    def check_lang(self, folder):
        items = os.listdir(folder)
        for item in items:
            _, extension = os.path.splitext(item)
            if extension in self.languages:
                print(f'{item} is written in {self.languages[extension]}')


    def get_folder(self): 
        folder_selected = askdirectory()
        if folder_selected:
            self.dirs['code'] = folder_selected
            self.folder_display.configure(text=folder_selected)
            self.folder = folder_selected
            self.check_lang(self.folder)
            
            return self.folder
        
    def write_txt(self, email, path):
        with open(path, 'w') as file:
            file.write(email)
        file.close()

   
    def gather_inputs(self):
        template = self.template_dropdown.get()
        self.guiInput['template'] = template
        email = self.email_entry.get()
        self.dirs['email'] = email
        self.write_terraform()
        self.put_file()


    def destroy_template_and_zip(self, clientPath, template, zip, txt):
        print(f'clientfolder: {clientPath}, template: {template} zipfile {zip} txt {txt}')
        deleteTxt = os.remove(txt)
        delete2 = os.remove(template)
        delete3 = os.remove(zip)
        delete1 = shutil.rmtree(clientPath)
        
    
    def destroy_resources(self):
        aws_access_key_id = self.credentials['AccessKeyId']
        aws_secret_access_key = self.credentials['SecretAccessKey']
        aws_session_token = self.credentials['SessionToken']

        
        lambda_function_name = 'Destroy_resources'
        
        lambda_client = boto3.client('lambda', 
                                     aws_access_key_id=aws_access_key_id,
                                     aws_secret_access_key=aws_secret_access_key,
                                     aws_session_token=aws_session_token,
                                     region_name='eu-central-1')  

        folder = self.generate_name_tag_db()
                
        user_id = self.userId.get('userid')

        payload = {'directory': folder,
                   'userid': user_id}

        response = lambda_client.invoke(
            FunctionName=lambda_function_name,
            InvocationType='RequestResponse',  
            Payload=json.dumps(payload)
        )

        status_code = response['StatusCode']
        response_payload = json.loads(response['Payload'].read().decode('utf-8'))

        clientFolder = self.dirs['client_path']
        template = self.dirs['highest_template']
        zip = self.dirs['zip']
        txtPath = os.path.join(clientFolder, 'email.txt')

        self.del_ips_from_db()
        self.del_folder_from_S3()
        self.destroy_template_and_zip(clientFolder, template, zip, txtPath)

        print(status_code)
        print(response_payload)

    def decode_user_token(self):
        id_token = jwt.decode(self.rawToken['rawtoken'], options={"verify_signature": False})
        wholeDecodedToken = id_token.get('sub')
        splitToken = wholeDecodedToken.split(':')
        usableToken = splitToken[-1]
        self.userId['userid'] = usableToken
        return usableToken
        

    def authenticate(self):
        identity_client = boto3.client('cognito-identity', region_name='eu-central-1')
        sts_client = boto3.client('sts')
        
        IDENTITY_POOL_ID = 'eu-central-1:0000000000000000000000'
        
      
        ROLE_ARN = 'arn:aws:iam::000000000000:role/service-role/cognito_role'
        
      
        identity_response = identity_client.get_id(IdentityPoolId=IDENTITY_POOL_ID)
        identity_id = identity_response['IdentityId']
        
      
        oidc_token_response = identity_client.get_open_id_token(IdentityId=identity_id)
        token = oidc_token_response['Token']

        self.rawToken['rawtoken'] = token
        
        assume_role_response = sts_client.assume_role_with_web_identity(
            RoleArn=ROLE_ARN,
            RoleSessionName='CognitoAssumedSession',
            WebIdentityToken=token
        )
        
        self.credentials = assume_role_response['Credentials']


        print(self.credentials)
        return self.credentials

    
    def check_auth(self):
        try:
            authcall = self.authenticate()
            if authcall is None:
                return ('unauth')
            else:
                return ('auth')
        except Exception as e:
            return 'unauth'
        
    def put_file(self):
        bucket_name = 'autoforge'
        zipName = self.generate_client_folder_name()  
        getClientFolder = self.construct_dir_structure()
        print(f'getClientFolder')
       
        parent = os.path.dirname(getClientFolder)
        print(f'parent {parent}')
        archive = shutil.make_archive(getClientFolder, 'zip', root_dir=parent, base_dir=os.path.basename(getClientFolder))
        zipfile = getClientFolder + '.zip'
        self.dirs['zip'] = zipfile
        
      
        aws_access_key_id = self.credentials['AccessKeyId']
        aws_secret_access_key = self.credentials['SecretAccessKey']
        aws_session_token = self.credentials['SessionToken']


        s3_client = boto3.client('s3',
                             aws_access_key_id=aws_access_key_id,
                             aws_secret_access_key=aws_secret_access_key,
                             aws_session_token=aws_session_token)
        
        with open(archive, 'rb') as data:
            s3_client.upload_fileobj(data, bucket_name, zipName + '.zip')

    def del_folder_from_S3(self):
        bucket = 'autoforge'
        folderPath = self.generate_s3_folder_path() 
        s3_client = boto3.client('s3',
                                 aws_access_key_id=self.credentials['AccessKeyId'],
                                 aws_secret_access_key=self.credentials['SecretAccessKey'],
                                 aws_session_token=self.credentials['SessionToken'])
        
        objectsToDelete = s3_client.list_objects_v2(Bucket=bucket, Prefix=folderPath)

        for obj in objectsToDelete.get('Contents', []):
            s3_client.delete_object(Bucket=bucket, Key=obj['Key'])

        s3_client.delete_object(Bucket=bucket, Key=folderPath)

                     
    # called by construct_new_subnet
    # def get_network_info(self):  
    ###     region = ('eu-west-2')
    #     aws_access_key_id = self.credentials['AccessKeyId']
    #     aws_secret_access_key = self.credentials['SecretAccessKey']
    #     aws_session_token = self.credentials['SessionToken']
    #     vpc_id = 'vpc-059db6e2661ea33c7'
    #     clnt = boto3.client('ec2',
    ###                          region,   
    #                          aws_access_key_id=aws_access_key_id,
    #                          aws_secret_access_key=aws_secret_access_key,
    #                          aws_session_token=aws_session_token)
    #     response = clnt.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    #     allSubnets = []
    #     for subnet in response['Subnets']:
    #         allSubnets.append(subnet['CidrBlock'])
    #     highestSubnet = allSubnets[0] if allSubnets else None
    #     countSubnets = len(allSubnets)
        # print(f'list {allSubnets}')
        # print('highest', highestSubnet)
        
        # return highestSubnet, countSubnets
    
    def get_ips_from_db(self):
        dynamodb = boto3.resource('dynamodb', region_name='eu-central-1',
                              aws_access_key_id=self.credentials['AccessKeyId'],
                              aws_secret_access_key=self.credentials['SecretAccessKey'],
                              aws_session_token=self.credentials['SessionToken'])

        tableName = 'project'
        table = dynamodb.Table(tableName)

        response = table.scan()
        items = response.get('Items', [])
 
        sortedItems = sorted(items, key=lambda x: x.get('count', 0), reverse=True)

        if sortedItems:
            maxIp = sortedItems[0]
            return maxIp['ip'], int(maxIp['count'])
        else:
            print('IPs not found')

    def write_to_db(self, ip1, count1, ip2, count2):
        dynamodb = boto3.resource('dynamodb',
                              region_name='eu-central-1',
                              aws_access_key_id=self.credentials['AccessKeyId'],
                              aws_secret_access_key=self.credentials['SecretAccessKey'],
                              aws_session_token=self.credentials['SessionToken'])

        table_name = 'project'
        table = dynamodb.Table(table_name)
        userToken = self.decode_user_token()
        genName = self.generate_name_tag_db()

        items_to_write = [
        {'ip': ip1, 'count': count1, 'user_id': userToken, 'client': genName},
        {'ip': ip2, 'count': count2, 'user_id': userToken, 'client': genName}]

        for item in items_to_write:
            table.put_item(Item=item)

    def del_ips_from_db(self):
        dynamodb = boto3.resource('dynamodb',
                                  region_name='eu-central-1',
                                  aws_access_key_id=self.credentials['AccessKeyId'],
                                  aws_secret_access_key=self.credentials['SecretAccessKey'],
                                  aws_session_token=self.credentials['SessionToken'])

        table_name = 'project'
        table = dynamodb.Table(table_name)

        cidr1 = self.subnetsInUse.get('cidr1')
        cidr2 = self.subnetsInUse.get('cidr2')

        if cidr1:
            table.delete_item(Key={'ip': cidr1})

        if cidr2:
            table.delete_item(Key={'ip': cidr2})

    # called by write terraform
    def construct_new_subnets(self):
        self.subnetRange, _ = self.get_ips_from_db()
        highestSubnet = self.subnetRange
        print(highestSubnet)
        
        # Splits / from subnet
        ip, prefixlen = highestSubnet.split('/')
    
        # Splits ip address in to 4 octets.
        octets = ip.split('.')

        # Increments 3rd octet for 2 subnets
        octets[2] = str(int(octets[2]) + 1)
        newIp1 = '.'.join(octets)
        octets[2] = str(int(octets[2]) + 1)
        newIp2 = '.'.join(octets)
    
        # Reconstructing the subnet
        newCidr1 = newIp1 + '/' + prefixlen
        newCidr2 = newIp2 + '/' + prefixlen
        print(f'ip1 {newCidr1} ip2 {newCidr2}')

        print(f'list {self.amount}')

        latestSubnetCount = self.updated_subnet_count()
        count1, count2 = latestSubnetCount

        self.subnetsInUse.update({'cidr1': newCidr1, 'cidr2': newCidr2})

        self.write_to_db(newCidr1, count1, newCidr2, count2)
        
        return newCidr1, newCidr2
     
    def generate_s3_folder_path(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}/')
    
    def generate_ec2_key(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-key')
    
    def generate_pub(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-key.pub')

    def updated_subnet_count(self):
        curValue = self.amount[0]
        print(curValue)
        count1 = curValue + 1
        count2 = count1 + 1
        return count1, count2
    
    def generate_name_tag_db(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}')
    
    def generate_ec2_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-ec2')
    
    def store_value(self):
        _, getAmount = self.get_ips_from_db()
        print(f'return value {getAmount}')
        self.amount.append(getAmount)
        
    def generate_subnet_name_tag(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}')
    
    def generate_nacl_name_tag(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-nacl')
    
    def generate_alb_name_tag(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-alb')
    
    def generate_alb_subnet_name_tag(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-alb-subnet')
    
    def generate_cluster_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-cluster')

    def generate_container_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-container')
    
    def generate_ecs_service_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-service')
    
    
    def generate_task_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-task')
    
    def generate_container_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-container')
    
    def generate_client_target_group_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-target-group')
    
    def generate_load_balancer_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}-load-balancer')
        
    def generate_client_folder_name(self):
        getListValue = self.amount[0]
        increment = (getListValue - 1) / 2 + 1
        conv = int(increment)
        return (f'Client-{conv}')

    # called by write terraform
    def temp_copy_and_dyn_file_naming(self):
        getcwd = os.path.dirname(os.path.abspath(__file__)) 
        constructPath = os.path.join(getcwd, 'blueprints')

        constructPath2 = os.path.join(getcwd, 'templates')

        templates = glob.glob(os.path.join(constructPath2, 'template*.tf')) + \
                glob.glob(os.path.join(constructPath, 'template*.tf.j2'))

        numbers = [int(re.search(r'template(\d+).tf(\.j2)?', template).group(1))
               for template in templates 
               if re.search(r'template(\d+).tf(\.j2)?', template)]

        next_number = (max(numbers) if numbers else 0) + 1

        dst = os.path.join(constructPath2, f'template{next_number}.tf')

        shutil.copyfile(os.path.join(constructPath, 'blueprint1.tf.j2'), dst)
        return dst

    def construct_dir_structure(self):
        client = self.generate_client_folder_name()
        curdir = os.getcwd()
        print(f'curdir {curdir}')
        templateDir = 'templates'
        betweenDir = 'GUI'
        targetDir = 'client_dirs'
        

        client_dirs_path = os.path.join(curdir, betweenDir, targetDir)
        blueprintPath = os.path.join(curdir, betweenDir, 'blueprints')

        if os.path.isdir(client_dirs_path):
            client_path = os.path.join(client_dirs_path, client)
            self.dirs['client_path'] = client_path

        
        if not os.path.exists(client_path):
            os.makedirs(client_path)
            self.dirs['client_path'] = client_path
            fulltxtPath = os.path.join(client_path, 'email.txt')

            time.sleep(1)
            
           
            additional_folder = 'code'
            additional_folder_path = os.path.join(client_path, additional_folder)
            email = self.dirs['email']
            self.write_txt(email, fulltxtPath)
            code = self.dirs['code']
            shutil.copytree(code, additional_folder_path)
            
            
            if not os.path.exists(additional_folder_path):
                os.makedirs(additional_folder_path)
                print(f'Directory structure created: {additional_folder_path}')
            else:
                print(f'{additional_folder} already exists in {client}')
            
            print(f'Directory structure created: {client_path}')


            templatePath = os.path.join(curdir, betweenDir, templateDir)
            print(f'construct_path {templatePath}')
            templates = glob.glob(os.path.join(templatePath, 'template*.tf')) 
            print(templates)
            numbers = [int(re.search(r'template(\d+)\.tf', os.path.basename(template)).group(1))
               for template in templates 
               if re.search(r'template(\d+)\.tf', template)]
           
            if numbers:
                highest_number = max(numbers)
                highest_template = os.path.join(templatePath, f'template{highest_number}.tf')

                choiceInput = self.guiInput['template']

                templateMapping = {'python-development': 'playbook.yaml',
                           'php-development': 'playbook2.yaml',
                           'c-development': 'playbook3.yaml'}
                
                ansibleFile = templateMapping.get(choiceInput)
                
                ansible = os.path.join(blueprintPath, ansibleFile)
                clientAnsiblePath = os.path.join(client_path, ansibleFile)
                DatabaseTokenGenPath = os.path.join(blueprintPath, 'DatabaseTokenGen.py')

               
                self.dirs['ansible_template'] = ansible
                self.dirs['highest_template'] = highest_template
                rdsToken = self.dirs['rds_token']
                shutil.copy(DatabaseTokenGenPath, client_path)
                shutil.copy(highest_template, client_path)
                shutil.copy(ansible, client_path)
                
                chosenPath = clientAnsiblePath
                correctPath = os.path.join(client_path, 'playbook.yaml')
                if chosenPath != correctPath:
                    os.rename(chosenPath, correctPath)
                    
                else:
                    pass



                print(f'highest numbered template {highest_number}')
            else:
                print('no template found')
            print(f'{client} directory already exists in {targetDir}')
            
           
        else:
            templatePath = os.path.join(curdir, betweenDir, templateDir)
            print(f'construct_path {templatePath}')
            templates = glob.glob(os.path.join(templatePath, 'template*.tf')) 
            print(templates)
            numbers = [int(re.search(r'template(\d+)\.tf', os.path.basename(template)).group(1))
               for template in templates 
               if re.search(r'template(\d+)\.tf', template)]
           
            if numbers:
                highest_number = max(numbers)
                highest_template = os.path.join(templatePath, f'template{highest_number}.tf')
                shutil.copy(highest_template, client_path)
                print(f'highest numbered template {highest_number}')
            else:
                print('no template found')
            print(f'{client} directory already exists in {targetDir}')
        
        print(f'client path {client_path}')
        return client_path

    def write_terraform(self):
        templateInput = self.guiInput['template']
        
        templateMapping = {'fastwebapp': 'blueprint1.tf.j2',
                           'python-development': 'blueprint2.tf.j2',
                           'php-development': 'blueprint2.tf.j2',
                           'c-development': 'blueprint2.tf.j2'}
        templateFile = templateMapping.get(templateInput)

        dynamicTempName = self.temp_copy_and_dyn_file_naming()    
        template = self.env.get_template(templateFile)
        subnetValue, subnetValue2 = self.construct_new_subnets()
        subnetNameTag = self.generate_subnet_name_tag()
        print('tagvalue', subnetNameTag)
        naclNameTag = self.generate_nacl_name_tag()
        albNameTag = self.generate_alb_name_tag()
        albSubnetNameTag = self.generate_alb_subnet_name_tag()
        clientClusterName = self.generate_cluster_name()
        clientContainerName = self.generate_container_name()
        ecsServiceName = self.generate_ecs_service_name()
        taskName = self.generate_task_name()
        containerName = self.generate_container_name()
        targetGroupName = self.generate_client_target_group_name()
        loadBalancerName = self.generate_load_balancer_name()
        ec2Name = self.generate_ec2_name()
        ec2Key = self.generate_ec2_key()
        ec2Pub = self.generate_pub()

        
        renderedTemplate = template.render(subnet_cidr=subnetValue,
                                           subnet_name_tag=subnetNameTag,
                                           client_nacl_name_tag=naclNameTag,
                                           alb_name=albNameTag,
                                           subnet_alb_tag=albSubnetNameTag,
                                           subnet_alb_cidr=subnetValue2,
                                           client_cluster_name=clientClusterName,
                                           client_container_name=clientContainerName,
                                           ecs_service_name=ecsServiceName,
                                           task_name=taskName,
                                           container_name=containerName,
                                           target_group=targetGroupName,
                                           lb_name=loadBalancerName,
                                           ec2_name=ec2Name,
                                           ec2_key=ec2Key,
                                           ec2_pub=ec2Pub


                                           )
        

        outputFile = dynamicTempName.replace('.j2', '')
        with open(outputFile, 'w') as f:
            f.write(renderedTemplate)

    def write_ansible(self, ansible, rdsToken, fullpath): 
        playbook = self.env.get_template(ansible)
        
        context = {'vnc_password': '{{ vnc_password }}',
                   'directory': '{{ directory }}',
                   'item': '{{ item }}',
                   'mysql_token': rdsToken
        }

        renderedPlaybook = playbook.render(context)
        

        outputFile = fullpath.replace('.j2', '')
        with open(outputFile, 'w') as f:
            f.write(renderedPlaybook)
        

############################################### GUI ######################################################################

# initialize's main GUI window and additional widgets + buttons that call methods through lambda
    
    def init_gui(self):
        # Main window initialization
        ctk.set_appearance_mode("light")
        self.window = ctk.CTk()
        self.window.title("AutoForge")
        self.window.geometry("600x600")
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.advanced = Toplevel(self.window)
        self.advanced.title("Advanced settings")
        self.advanced.geometry("300x500")
        self.advanced.protocol("WM_DELETE_WINDOW", self.hide_advanced)
        self.advanced.withdraw()

        self.folder = ""  # folder to be selected by user

        # Main window widgets
        image = PhotoImage(file="GUI/background/logo.png")
        self.logo = ctk.CTkLabel(self.window, image=image,text="")
        #pack it with a top margin of 15 pixels but no bottom margin
        self.logo.pack(pady=(45, 0))

        try:   
            if self.ref == 'unauth':
                self.auth_label = ctk.CTkLabel(self.window, 
                text="Unauthenticated", 
                font=("San Fransisco", 20, "bold"), 
                text_color="red")
                self.auth_label.pack(pady=(0, 15))
            else:
                self.auth_label = ctk.CTkLabel(self.window, 
                text="Authenticated", 
                font=("San Fransisco", 20, "bold"), 
                text_color="#3EB489")
                self.auth_label.pack(pady=(0, 15))
        
        except Exception as e:
            print(f"error {e}")


        # Folder popup
        self.folder_label = ctk.CTkLabel(self.window, 
                                         text="Select folder:", 
                                         font=("San Fransisco", 15, "bold"), 
                                         text_color="black", 
                                         pady=8)
        self.folder_label.pack()

        self.folder_button = ctk.CTkButton(self.window, 
                                           text="Browse folder", 
                                           font=("San Fransisco", 15, "bold"), 
                                           text_color="white", corner_radius=8, 
                                           fg_color="#3EB489", 
                                           hover=True, 
                                           hover_color="#899499", 
                                           
                                           command=self.get_folder)
        self.folder_button.pack()

        self.folder_display = ctk.CTkLabel(self.window, 
                                           text="No folder selected", 
                                           font=("San Fransisco", 15, "bold"), 
                                           text_color="black")
        self.folder_display.pack()
        
        # Select template text
        self.template_label = ctk.CTkLabel(self.window, 
                                           text="Select template:", 
                                           font=("San Fransisco", 15, "bold"), 
                                           pady=10, 
                                           text_color="black")
        self.template_label.pack()

        # Template dropdown menu
        self.template_dropdown = ctk.CTkOptionMenu(self.window, values=["No selection", "fastwebapp", "python-development", "php-development", "c-development"], 
                                                   fg_color="#3EB489", 
                                                   hover=True, 
                                                   dropdown_hover_color="white", 
                                                   button_color="#3EB489", 
                                                   button_hover_color="#899499", 
                                                   dropdown_text_color="black", 
                                                   text_color="white", 
                                                   font=("San Fransisco", 15, "bold"), 
                                                   dropdown_font=("San Fransisco", 15, "bold"))
                                                    

        self.template_dropdown.pack()

        self.email_label = ctk.CTkLabel(self.window, 
                                        text="Enter email:", 
                                        font=("San Fransisco", 15, "bold"), 
                                        pady=10, 
                                        text_color="black")
        self.email_label.pack()

        self.email_entry = ctk.CTkEntry(self.window,
                                        font=("San Fransisco", 15, "bold"),
                                        text_color="black")
        self.email_entry.pack()


           # Submit button
        self.submitButton = ctk.CTkButton(self.window, 
                                                     text="Submit", 
                                                     font=("San Fransisco", 15, "bold"), 
                                                     text_color="white",
                                                     
                                                     corner_radius=8, 
                                                     fg_color="#3EB489", 
                                                     hover=True, 
                                                     hover_color="#899499", 
                                                     border_color="#3EB489",
                                                     command=self.gather_inputs) 
                                                     
        self.submitButton.pack(pady=(20,5))

        self.destroyButton = ctk.CTkButton(self.window, 
                                                     text="Destroy instance", 
                                                     font=("San Fransisco", 15, "bold"), 
                                                     text_color="white",
                                                     
                                                     corner_radius=8, 
                                                     fg_color="#FF0000", 
                                                     hover=True, 
                                                     hover_color="#899499", 
                                                     border_color="#3EB489",
                                                     command=self.destroy_resources) 
                                                     
        self.destroyButton.pack(pady=1)



        # Run the window
        self.window.mainloop()

    # Makes sure buttons are responsive called from init_gui(self)
    def advancedsettings(self):
        self.advanced.deiconify()

    def hide_advanced(self):
        self.advanced.withdraw()

    # Constantly updates ram slider while being moved
    def update_label(self):
        self.ram_label.configure(text=f'RAM: {self.ram_slider.get()} GB')
        self.ram_label.after(100, self.update_label)

    # Makes sure GUI closes properly
    def on_closing(self):
        self.window.quit()
        self.window.destroy()
        sys.exit()


if __name__ == "__main__":
    app_instance = App()