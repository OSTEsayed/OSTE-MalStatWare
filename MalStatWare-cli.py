import argparse
import os
import magic    #pip install python-magic
import hashlib
import time
import math
import pefile

def CheckExist(file_path):
    if os.path.exists(file_path):
        return True
    else:
        return False
def Get_info(file_path,types):
    file_info={}
    if 'all' in types :
        file_info['size']=get_file_size(file_path)
        file_info['type']=get_true_file_extension(file_path)
        file_info['name']=get_file_name(file_path)
        
        
        file_info['SHA-1']=get_sha1_file(file_path)
        file_info['SHA-256']=get_sha256_file(file_path)
        file_info['MD5']=get_md5_file(file_path)
        file_info['blake2b']=get_blake2b_file(file_path)

        file_info['ctime']= time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.stat(file_path).st_ctime))
        file_info['mtime']=  time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.stat(file_path).st_mtime))
        file_info['atime']= time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getatime(file_path)))
        
        file_info['entropy'] = calculate_file_entropy(file_path)
        if is_executable(file_path) :
            file_info['exe']="File is executable"
        else :
            file_info['exe']="File is NOT executable"
    return file_info

def get_file_name(file_path):
    return os.path.basename(file_path)

def get_file_size(file_path):
    if os.path.exists(file_path):
        size_bytes = os.path.getsize(file_path)
        size_kb = size_bytes / 1024  # Convert bytes to kilobytes
#        print(f"The size of the file '{file_path}' is {size_bytes} bytes ({size_kb:.2f} KB).")
        return size_bytes

def get_true_file_extension(file_path):
    if os.path.exists(file_path):
        mime = magic.Magic(mime=True)
        true_extension = mime.from_file(file_path).split('/')[1]
        return true_extension.lower()

def get_sha1_file(file_path):
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()

def get_sha256_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()    

def get_md5_file(file_path):
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()    
    
def sha1_directory(directory_path):
    sha1 = hashlib.sha1()
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(65536)  # Read in 64k chunks
                    if not data:
                        break
                    sha1.update(data)
    return sha1.hexdigest()

def get_blake2b_file(file_path):
    # Initialize BLAKE2b hash object
    blake2_hash = hashlib.blake2b()

    # Open the file in binary mode
    with open(file_path, 'rb') as f:
        # Read the file in chunks
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            # Update hash with data chunk
            blake2_hash.update(data)

    # Return hexadecimal digest of the hash
    return blake2_hash.hexdigest()
def calculate_file_entropy(file_path):
    # Dictionary to count occurrences of each byte value
    byte_counts = {}

    # Total number of bytes in the file
    total_bytes = 0

    # Open the file in binary mode
    with open(file_path, 'rb') as f:
        # Read the file in chunks
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            total_bytes += len(data)
            # Count occurrences of each byte value
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

    # Calculate entropy using Shannon entropy formula
    entropy = 0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy

def search_inDirectory(target_sha256,Search_path):
    list_of_paths=[]
    for root, _, files in os.walk(Search_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if get_sha256_file(file_path) == target_sha256:
                list_of_paths.append(file_path)
    return list_of_paths

def is_executable(file_path):
    return os.access(file_path, os.X_OK)

def analyze_pe_header(file_path):
    try:
        pe = pefile.PE(file_path)
        print("PE Header Analysis:")
        print(f"Machine: {pe.FILE_HEADER.Machine}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"Time Date Stamp: {pe.FILE_HEADER.TimeDateStamp}")
        print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"Section Headers:")
        for section in pe.sections:
            print(" \t {}: Virtual Address: {}, Size of Raw Data: {}".format(section.Name.decode().rstrip('\x00'),hex(section.VirtualAddress),hex(section.SizeOfRawData)))
    except Exception as e:
        print(f"Error analyzing PE header: {e}")

def main():    
    parser = argparse.ArgumentParser(description='MetaStatWare-cli [Action] [option] [value] :  exampl MetaStatWare-cli -f file.text -i ALL')
    # Add the -l option
    parser.add_argument('-f', '--file', type=str,help='Specify the file path Example : directoy/exampl.txt')
    parser.add_argument('-i', '--info', help='Gather file information [ALL,SHA-1,SHA-256,MD5,SIZE,TYPE] Default==ALL')
    parser.add_argument('-s', '--search', help='Search if the file exist in chosen directory Example: /home/directoryToSearchIn/')
    parser.add_argument('-pe', '--pefile', action='store_true',help='Perform Basic PE header analysis.')
#    parser.add_argument('-e', '--example', action='store_true') Action store true make it store true if the argument exits.

    # Parse the command-line arguments
    args = parser.parse_args()
    print ("\n \t.---------------------------------------.\n \t|\t  ┳┳┓  ┓┏┓    ┓ ┏ \t\t|\n \t|\t  ┃┃┃┏┓┃┗┓╋┏┓╋┃┃┃┏┓┏┓┏┓ \t|\n \t|\t  ┛ ┗┗┻┗┗┛┗┗┻┗┗┻┛┗┻┛ ┗  \t|\n \t`_______________________________________`\n            ");
    # Check if the -f option is provided
    if args.file:
        
        if CheckExist(args.file) == False:
            print("# The file inserted does not exist please verify the path.")
        else:
            if args.info:
                file_info=Get_info(args.file,args.info)
                print(f"\n # {file_info['name']} Information : \n File Creation : \t {file_info['ctime']} \n File modification : \t {file_info['mtime']} \n File Acess : \t \t {file_info['atime']} \n File Size (Bytes) : \t {file_info['size']} \n File Extension : \t {file_info['type']} \n File SHA-1 : \t \t {file_info['SHA-1']} \n File SHA-256 : \t {file_info['SHA-256']} \n File MD5 : \t \t {file_info['MD5']} \n File Blake2b : \t {file_info['blake2b']}  \n File Entropy : \t {file_info['entropy']} \n File : \t {file_info['exe']} \n")

            if args.pefile:
                analyze_pe_header(args.file)
                
            if args.search:
                file_info=Get_info(args.file,"all")
                search_result = search_inDirectory (file_info['SHA-256'],args.search)
                print(f"\n #)Search Results in Directory [ {args.search} ] : \n Number of files Found : \t {len(search_result)} ")
                if len(search_result) > 0 : 
                    for item in search_result:
                        print(f"\n-)  {item}")      
            
    else:
        print('For more Information on how to use "MalStatWare" type -h or --help .')


if __name__ == "__main__":
    main()
    
