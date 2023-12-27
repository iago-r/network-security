import subprocess

def snmptranslate(variable):
    
    # read rows in file
    with open(variable, 'r') as file:
        rows = file.readlines()

    # operate rows
    for i, row in enumerate(rows):
    
        # split in 2 commands
        split_command = rows[i].split('=')
        
        if len(split_command) > 1: 
            oid = split_command[0].strip()
            value = split_command[1].strip()

            try:  
                # command translate
                command = ["snmptranslate", "-Ta", oid]
                
                result = subprocess.run(command, capture_output=True, text=True, check=True)

                # variable tranlate
                command_output = result.stdout.strip()

                # replace old row to translated row
                rows[i] = row.replace(rows[i], f'{command_output} = {value}\n')
                
            except subprocess.CalledProcessError as e:
                print(f"Command Error: {e}")
    
    # write all changes in same file
    with open(variable, 'w') as arquivo:
        arquivo.writelines(rows)



    

