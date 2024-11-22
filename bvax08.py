import pdb; 
import io
import contextlib
import subprocess
import sys
import time
import json  
from concurrent.futures import ThreadPoolExecutor, as_completed
import psycopg2
from psycopg2.extras import RealDictCursor
#start_time = time.time()
from openai import OpenAI
client = OpenAI(api_key='TO BE DEFINED')

class Messaging:
    def __init__(self, db_config):
        self.db_config = db_config
        self.conn = psycopg2.connect(**db_config)
        self.conn.autocommit = True
        # Create a cursor object
        cur = self.conn.cursor()
        # Set the search path to your schema
        schema_name = 'sch01'
        cur.execute(f'SET search_path TO {schema_name}')
        
    def send_message(self, sender, receiver, content, task_id, task_type):
        """Send a message from a sender to a receiver, storing it in the database."""
        query = "INSERT INTO messages (sender, receiver, content, read, task_id, task_type) VALUES (%s, %s, %s, FALSE, %s, %s);"
        with self.conn.cursor() as cur:
            cur.execute(query, (sender, receiver, content, task_id, task_type))
        with open("log01.txt", "a") as file:
            file.write(sender + ": "+ content + ".\n")

    def read_message(self, receiver):
        """Retrieve a single unread message for a specific receiver and mark it as read."""
        message = None
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Select the first unread message for the receiver
            cur.execute("SELECT * FROM messages WHERE receiver = %s AND read = FALSE ORDER BY timestamp ASC LIMIT 1;", (receiver,))
            message = cur.fetchone()
            if message:
                # Mark the retrieved message as read using its ID
                cur.execute("UPDATE messages SET read = TRUE WHERE id = %s;", (message['id'],))                
        return message


class ClassCyberBlueVirtualAgent():
    
    def __init__(self, identifier, messaging_system, received_message, last_message, current_thread):
        self.identifier = identifier
        self.messaging_system = messaging_system
        self.received_message = received_message
        self.last_message = last_message
        self.current_thread = current_thread
    
    # TECHNICAL FUNCTIONS
        
    def basicQuestionToAskForParameters(self):
        response = client.chat.completions.create(
            #model="gpt-4o-mini",
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a CyberSecurity Expert"},
                {"role": "assistant", "content": 'Take into account following CONTEXT: ' + self.current_thread},
                {"role": "user", "content": "Prepare a questions to ask for parameters for this last task requested by the user. Be very short, smart and concrete with the question. No more than 5 parameters"}
                ]
                )
        return(response.choices[0].message.content)
    
    def basicQuestionToOpenAI(self, p):
        response = client.chat.completions.create(
            #model="gpt-4o-mini",
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a CyberSecurity Expert"},
                {"role": "assistant", "content": "You have access to Internet"},
                {"role": "assistant", "content": "You can make questions to GPT4 LLM through OpenAI API"},
                {"role": "assistant", "content": "You can make searches in Google through Google Search API"},
                {"role": "assistant", "content": "You can execute Python scripts"},
                {"role": "assistant", "content": 'Take into account following CONTEXT: ' + self.current_thread},
                {"role": "user", "content": p}
                ]
                )
        return(response.choices[0].message.content)

                
    def exec_python_file(self):
        # Run the external .py file and capture its output
        result = subprocess.run(["python3", "/home/jbru/va01/helloworld.py"], capture_output=True, text=True)
        # Print the output from the external script
        print(result.stdout)
        # Print any errors from the external script
        if result.stderr:
            print("Errors:", result.stderr)
               
        
    # COGNITIVE FUNCTIONS
    def core_cognitive_process(self):
        
        pass
            
    # PERCEPTION FROM DIRECT HUMAN ORDER INTERFACE
    def cp_perception2(self):
        
        received = False
        while not received:
            self.received_message = self.messaging_system.read_message('CyberBlueVirtualAgent01')        
            if self.received_message is not None:                        
                received = True                
                #print("#" + self.received_message['sender'] + ": " + self.received_message['content'])
            else:
                received = False 
                #time.sleep(1)  # Delay for 5 seconds           
            return(received)
    
    
    def cp_perception(self):
        # PERCEPTION FROM DIRECT HUMAN ORDER INTERFACE
        self.received_message = self.messaging_system.read_message('CyberBlueVirtualAgent01')        
        if self.received_message is not None:                        
            r = True                
            #print("#" + self.received_message['sender'] + ": " + self.received_message['content'])
        else:
            r = False 
            #time.sleep(0)  # Delay for 5 seconds           
        return(r)
        
    def cp_attention(self):
        return(0)
        
    def cp_memory(self):
        # short-term memory, working memory, long-term memory, and profile memory.
        self.received_message['content']
        
        
        return(0)
    
    def cp_learning(self):
        return(0)
    
    def cp_language_communication(self, type_sentence):
        if type_sentence == "PrepareAnswer":
            #p =  "Please act as this PROFILE: " + core_profile + ". Answer following question. QUESTION: " + message_for_a['content'] #+ "Take into account previous context. CONTEXT: " + self.current_thread;
            #print(self.received_message['content'])            
            #p =  "Please act as CyberSecurity Expert. Answer following question. QUESTION: " + self.received_message['content'] + " Take into account previous context. CONTEXT: " + self.current_thread + ". Do not start the the asnwer with a name."            
            p = self.received_message['content']             
            r=self.basicQuestionToOpenAI(p)                       
            self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', r, self.received_message['task_id'], self.received_message['task_type']) 
            self.current_thread = self.current_thread + ".\n" + "Manager" + ": "+ self.received_message['content'] + ".\n"
            self.current_thread = self.current_thread + ".\n" + "CyberBlueVirtualAgent01" + ": "+ r + ".\n"
            #Summarize current_thread to avoid growing too much.  
            response = client.chat.completions.create(
            #model="gpt-4o-mini",
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a Writer Expert"},
                {"role": "user", "content": "Summarize the following TEXT to two pages: " + self.current_thread}
                ]
                )
            self.current_thread = response.choices[0].message.content
        else: 
            if type_sentence == "PrepareAnswerForEndProcess":
                r="The code was executed. You can start again"
                self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', r, self.received_message['task_id'], self.received_message['task_type']) 
                
            else:
                if type_sentence == "CancelConversation":
                    r="This question falls outside the scope of my responsibilities. Thank you, and goodbye."
                    self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', r, self.received_message['task_id'], self.received_message['task_type'])                        
        
        self.last_message = r
        print("\nCyberBlueVirtualAgent###########################################################:\n",  r)
        return(True)
        
    def cp_language_communication2(self, type_sentence):
        if type_sentence == "CancelConversation":
                r="This question falls outside the scope of my responsibilities. Thank you, and goodbye."
                self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', r, self.received_message['task_id'], self.received_message['task_type'])                        
        else:
            if type_sentence == "PrepareAnswer":
                #p =  "Please act as this PROFILE: " + core_profile + ". Answer following question. QUESTION: " + message_for_a['content'] #+ "Take into account previous context. CONTEXT: " + self.current_thread;
                #print(self.received_message['content'])            
                #p =  "Please act as CyberSecurity Expert. Answer following question. QUESTION: " + self.received_message['content'] + " Take into account previous context. CONTEXT: " + self.current_thread + ". Do not start the the asnwer with a name."            
                p = self.received_message['content']             
                r=self.basicQuestionToOpenAI(p)                       
                self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', r, self.received_message['task_id'], self.received_message['task_type']) 
            else:    
                if type_sentence == "AskForParameters":
                    r=self.basicQuestionToAskForParameters()
                    self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', r, self.received_message['task_id'], self.received_message['task_type']) 
                    
        
        # Add to current thread
        self.current_thread = self.current_thread + ".\n" + "Manager" + ": "+ self.received_message['content'] + ".\n"
        self.current_thread = self.current_thread + ".\n" + "CyberBlueVirtualAgent01" + ": "+ r + ".\n"  
        #Summarize current_thread to avoid growing too much.               
            
        #print("#CyberBlueVirtualAgent:",  r)
        return(True)
        
        
        
    def cp_reasoning(self):
        
        return(0)
        
        
    def cp_moderation(self):
        return(True)
        
    def ask_for_approval(self):
        
        pass
        
    def cp_reasoning_is_request_for_llm(self):        
        if 'YES' == self.basicQuestionToOpenAI("The following request can be answered only with LLM, or do we need additional resources?. Please answer only YES or NOT. REQUEST: "  + self.received_message['content']):
            return(True)
        else:
            return(False)
        
    def cp_reasoning_is_request_for_script(self):
        print("cp_reasoning_is_question_for_resources(self):")
        r=self.basicQuestionToOpenAI("The next request is asking for Python Code?. Please answer only YES or NOT. REQUEST: "  + self.received_message['content'])
        print("RESULT: " + r)
        if 'YES' == r:
            print('YES ########################################')
            return(True)
        else:
            print('NO ########################################')
            return(False)        
        pass
        
    def cp_reasoning_request_classifier(self):
        system_classification_prompt = """
            You are a CiberSecurity virtual agent designed to classify requests related to cybersecurity, general IT, and knowledge requests.
            You have to analyze the request and provide the following information:
            1. The type of request: Informational, Action-Oriented, or Analytical.
            2. Does it require external resources (e.g., Python code execution, Google search, database connection) or can it be answered by the internal LLM Open AI API(GPT4)?
            3. If relevant, map the request to one of these Blue Team functionalities: Threat Detection and Monitoring, Vulnerability Management, Incident Response, Threat Intelligence Gathering, 
                Forensics and Log Analysis, Security Policy Enforcement.
            Provide the output in a List of words for python: "["Type of Question", "resource_needed", "blue_team_functionality"]"
            """
        
        response = client.chat.completions.create(
            #model="gpt-4o-mini",
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_classification_prompt},
                {"role": "user", "content": "Classify this request: " + self.received_message['content']}
                ]
                )
                
        classification_result = response.choices[0].message.content
        return classification_result
    
    # CYBERSECURITY FUNCTIONS
    
    # General Netowrk and System Reconnaissance
    
    # Nmap/Zenmap: For network scanning and vulnerability assessments.
    # Wireshark: For packet analysis and network traffic monitoring.
    # Maltego: For mapping relationships between threat actors, IPs, and domains.
    # Splunk/ELK Stack: For log analysis and real-time monitoring of suspicious activities.
    # MITRE ATT&CK Framework: To identify known adversary TTPs and apply them to the local context.
    
    def NMAPNetworkSystemRecon(self):
        action_nr = 200
        n=0
        while n < action_nr: 
            print('\n#NEW LOOP ########################################################################\n')
            # High Level Mission: Network and Systems Reconaissance
            action = 'I need you to prepare a Cyber reconaissance task to get Cyberspace information to defend our organization'
            action = action + 'We have to work with Python and NMAP.' 
            action = action + 'This task could be one of the follow: ' 
            action = action + 'Host Discovery, ARP Scan, TCP SYN Scan (Stealth Scan), TCP Connect Scan, UDP Scan, Scan Specific Ports, Service Version Detection, Operating System Detection, Aggressive Scan,'
            action = action + 'Traceroute, Vulnerability Scanning, Brute Force Attack Scans, Banner Grabbing, Decoy Scanning, Fragmented Packets, Idle Scan (Zombie Scan), Default Script Scan,'
            action = action + 'HTTP Enumeration, SMB Scanning, TCP ACK Scan (Firewall Detection), Window Scan, IPv6 Scanning,  Increase Speed (Timing Templates), Scan Fewer Ports, XML Output, Greppable Output,'
            action = action + 'Please select only one action and be concrete.'
            print('\nNMAPNetworkSystemRecon ############################################################:\n' + action + '\n')
            self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', action, n, 'request_action')   
            self.core_cbva_core_process2()
            self.cp_perception2()
            #self.wait_message()
            # print('#Cyber: ' + self.received_message['content'])            
            # Ask to prepare code
            action = "OK. With this selection, please develop a Python code, using NMAP. We do not need scripts for loading the Python packets as we already have in the setup"
            print('\nNMAPNetworkSystemRecon ############################################################:\n' + action + '\n')
            self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', action, n, 'write_code')
            self.core_cbva_core_process2()
            self.cp_perception2()
            #self.wait_message()            
            #print('#Cyber: ' + self.received_message['content'])            
            # Set Parameters
            #action = "OK. Parametrize the code for network in the scope '88.18.141.*' 
            action = "OK. Parametrize the code for network in the scope '192.168.1.0/24'"
            print('\nNMAPNetworkSystemRecon ############################################################:\n' + action + '\n')
            self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', action, n, 'parametrize')
            self.core_cbva_core_process2()
            self.cp_perception2()
            #self.wait_message()
            #print('#Cyber: ' + self.received_message['content'])          
            # Clean code
            action = "Please redo. Make sure you only provide the ONLY the generated python code. No comments. No introduction. No ```python. No ```"
            print('\nNMAPNetworkSystemRecon ############################################################:\n' + action + '\n')
            self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', action, n, 'refine_code')            
            self.core_cbva_core_process2()
            self.cp_perception2()
            #self.wait_message()            
            #print('#Cyber: ' + self.received_message['content'])            
            # Ask to execute the code
            action = "EXEC"
            self.messaging_system.send_message('CyberBlueVirtualAgent01', 'CyberBlueVirtualAgent01', action, n, 'execute_code')
            print('\nNMAPNetworkSystemRecon ############################################################:\n' + action + '\n')
            self.core_cbva_core_process2()
            self.cp_perception2()
            #self.wait_message()
            # print('#NMAPNetworkSystemRecon: ' + self.received_message['content'] + '\n')            
            n=n+1            
            print('#\nEND OF LOOP ########################################################################\n')
        print("\nLOOPS ENDED ########################################################################\n")     
    
    def run(self):
        self.NMAPNetworkSystemRecon()
                              
    def core_cbva_core_process2(self):    
        if self.cp_perception() == True: 
            # print('# Perception: ' + self.received_message['content'] + '\n')
            # First is to classify the type of perception. This is done by memeory. 
            if self.received_message['content'] == 'EXEC': # Exit from Application    
                with open("/home/jbru/va01/exec_action.py", "w") as file:
                    file.write(self.last_message)
                # SAVE CODE TO SQL
                
                #Execute the code
                try:
                    # Run the subprocess with a 15-minute timeout
                    result = subprocess.run(
                        ["python3", "/home/jbru/va01/exec_action.py"],
                        capture_output=True,
                        text=True,
                        timeout=15*60  # Timeout of 5 minutes
                    )
                    # Check if the command completed successfully
                    if result.returncode == 0:
                        print("Subprocess completed successfully.")
                        print(result.stdout)  # Output of the subprocess
                        with open("/home/jbru/va01/log.txt", "a") as file:
                            file.write("NEW RESULTS ##########################################################\n")
                            file.write(result.stdout)
                            # SAVE RESULTS TO SQL
                    else:
                        print(f"Subprocess exited with return code {result.returncode}")
                        print(result.stderr)  # Error message from the subprocess
                        with open("/home/jbru/va01/log.txt", "a") as file:
                            file.write("NEW ERRORS ##########################################################\n")
                            file.write(result.stderr)
                        if result.stderr:
                            print("Errors:", result.stderr)
                            # SAVE ERRORS TO SQL
                            
                except subprocess.TimeoutExpired as e:
                    print(f"Subprocess timed out after {e.timeout} seconds.") 
                    with open("/home/jbru/va01/log.txt", "a") as file:
                        file.write("NEW ERRORS ##########################################################\n")
                        file.write(f"Subprocess timed out after {e.timeout} seconds.")
                
                
                self.cp_language_communication("PrepareAnswerForEndProcess") # Continue conversation                
            else:
                self.cp_language_communication("PrepareAnswer") # Inform this is out of scope, and end conversation

    
    def core_cbva_core_process(self):
        while True:
            if self.cp_perception() == True:                
                # First is to classify the type of perception. This is done by memeory. 
                if self.received_message['content'] == 'EXEC': # Exit from Application    
                    with open("/home/jbru/va01/exec_action.py", "w") as file:
                        file.write(self.last_message)
                    #Execute the code
                    #result = subprocess.run(["python3", "/home/jbru/va01/exec_action.py"], capture_output=True, text=True, timeout=15*60)
                    try:
                        # Run the subprocess with a 15-minute timeout
                        result = subprocess.run(
                            ["python3", "/home/jbru/va01/exec_action.py"],
                            capture_output=True,
                            text=True,
                            timeout=15*60  # Timeout of 5 minutes
                        )
                        # Check if the command completed successfully
                        if result.returncode == 0:
                            print("Subprocess completed successfully.")
                            print(result.stdout)  # Output of the subprocess
                        else:
                            print(f"Subprocess exited with return code {result.returncode}")
                            print(result.stderr)  # Error message from the subprocess
                    except subprocess.TimeoutExpired as e:
                        print(f"Subprocess timed out after {e.timeout} seconds.")
                    # Print the output from the external script
                    print(result.stdout)
                    with open("/home/jbru/va01/log.txt", "a") as file:
                        file.write("NEW RESULTS ##########################################################\n")
                        file.write(result.stdout)
                    # Print any errors from the external script
                    if result.stderr:
                        print("Errors:", result.stderr)
                    self.cp_language_communication("PrepareAnswerForEndProcess") # Continue conversation                
                else:
                    self.cp_language_communication("PrepareAnswer") # Inform this is out of scope, and end conversation
                      
           
######################################################################################
# Main System Class 

class MainSystem:
  
    def __init__(self):
        db_config = {
            'dbname': 'va01',
            'user': 'TO BE DEFINED',
            'password': 'TO BE DEFINED',
            'host': '192.168.1.95',
            'port': '5432'}
        
        self.messaging_system = Messaging(db_config)  
    
        self.a = ClassCyberBlueVirtualAgent("CyberBlueVirtualAgent01", self.messaging_system, '', '', '')        
    
    def start(self):
        self.a.run()     

    
 
if __name__ == "__main__":

    system = MainSystem()
    system.start()    
        
