'''
Name: offsecn00b
Date: 2/28/2015

Objective: 

BACKGROUND:
The volatility framework is an industry recognized framework for conducting memory forensics. Volatility is designed primarily to be a command line 
tool though it is possible to use volatility as a library. The problem with using volatility as a commmand line only tool is it limits your ability to analyzing a single
file(memory dump) at a time. I imagined a scenario where we needed to analyze many memory dumps and perform a specific function. Scripting volatility functionality would
allow for automating what would otherwise be a manual tasks of running commands against each memory dump individually from the command line.

Objective: 
The objective of this script is to open a memory dump file and first validate if it is a windows memory dump. ( Linux dumps would be ignored) THe script will then proceed 
to create a valid Volatility config using assigned the detected profile type. Once the config is built for that specific windows dump the script initiates an appropriate scan of the 
memory using either the Connscan(for xp/win2k3 variant) or Netscan(windows vista and above) plugins. These plugins scan memory for active network connections. The script extracts
the remote ip address and adds it to a list. There is a function that will perform a dns lookup for those ips to attempt to find any hosts names associated. Finally the script
takes the list of remote ip connections and dns hostnames and bounces them against a given list of kNown "bad hosts" . In this way you can scan many memory dumps and output any active 
connections to known bad ips or hostnames. 

Future work: 
Implement logging functionality
Implement command line parsing for globals
Implement support for Linux
Implement Multiprocessing current process time is ~80 seconds per image

'''


#importing required volatility library
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.win32 as win32
import volatility.plugins as plugins
import volatility.utils as utils

#importing socket, time and os for network, time and file operations
import socket
import time
import os

#DEFINE GLOBALS for search directory and file with bad hosts listed
SEARCHDIR = 'C:\Users\guest1\Desktop\windows'
BADHOSTS = 'C:\\Users\\guest1\\Desktop\\badhosts.txt'

#ver 
def GetVersion(configs):
    try:
        #initiate volatility plug that scans the image and retrieves image info, works on windows only will error out for others
        m = plugins.imageinfo.ImageInfo(configs)
        #calls function to print out image info
        PrintInfo(m)
        #search results for the field of suggested profile names. Extract string and return profile value in format WinXPSP2x86, WinXPSP3x86 etc
        for i in m.calculate():
            if not i[0].find("Suggested") == -1:
                ver = i[1].split(',')
                return ver[0]
            else:
                
                print i
    except: 
        print "invalid non-windows image type found, did you try scanning a Unix memory dump?"
        return None


#defines confg file for each image
def GetConfig(theFile):

#define Baseline Config
    base_conf = {'profile': None,
                 'use_old_as': None, 
                 'kdbg': None, 
                 'help': False, 
                 'kpcr': None, 
                 'tz': None, 
                 'pid': None, 
                 'output_file': None, 
                 'physical_offset': None, 
                 'conf_file': None, 
                 'dtb': None, 
                 'output': 'text', 
                 'info': None, 
                 'location': theFile, 
                 'plugins': None, 
                 'debug': None, 
                 'cache_dtb': True, 
                 'filename': theFile,
                 'cache_directory': None, 
                 'verbose': None, 'write':False}
    #create volatility config object
    configs = conf.ConfObject()
    #set location value to file name
    configs.LOCATION = theFile
    #register global options for volatility functions/plugins to use
    registry.register_global_options(configs, commands.Command)
    registry.register_global_options(configs, addrspace.BaseAddressSpace)
    
    #run imgageinfo plug to get extract image profile 
    version = GetVersion(configs) 
    if not version == None:
        #using the base line config update our config object
        for k,v in base_conf.items():
            configs.update(k, v)
        #set config object profile to the version extracted 
        configs.update('profile', version)    
        #return config object to be used with our plugins
        return configs
    else:
        return None


        
        
#Because windows has different impelmentation of network stack between versions we need to use two plugings Connscan and Netscan based on the memory dump img profile
def ConnScan(config):
    #if the img profile is xp/w2k3 variant use volatility Connscan plugin
    if config.PROFILE.count('XP') > 0 or config.PROFILE.count('2003') > 0:
        
        try:
            t = plugins.connscan.ConnScan(config)
            
            listIP = []
            #calculate is a basic function all objects in volatility have. It yields the data elements of the object. We loop through each object and print
            # each TCP connection
            for x in t.calculate():
                local = "{0}:{1}".format(x.LocalIpAddress, x.LocalPort)
                remote = "{0}:{1}".format(x.RemoteIpAddress, x.RemotePort)
                remoteIP = "{0}".format(x.RemoteIpAddress)
                print ('connections found: %s ===> %s'%(local, remote))
                #build list of remote ip connections
                if not remoteIP in listIP:
                    listIP.append(remoteIP) 
            
            return listIP
        except:
            return None
     
       
    else:
        #non XP windows image will execute similar plugin called Netscan which also prints UDP connections. 
        #remote IP connections are captured, extracted and returned.
        try:
            t = plugins.netscan.Netscan(config)
        
            listIP = []
            for x in t.calculate():
                if x[1].count('UDP') > 0:
                    if not str(x[2]) == '0.0.0.0' and not str(x[2]) == '::' and not str(x[2]) == '::1':
                        print ("We found an active UDP conneciton %s" % (x[2]))
                else:
                    # After examining the volatility code for the Netscan.Calculate() functon we were able to determine the location of each member value below
                    local = "{0}:{1}".format(x[2], x[3]) #localip, localport
                    remote = "{0}:{1}".format(x[4], x[5])# remoteip, remoteport
                    remoteIP = "{0}".format(x[4])
                    #print connection list
                    print ('connections found: %s ===> %s'%(local, remote))
                    if not remoteIP in listIP and not str(remoteIP) == '0.0.0.0' and not str(remoteIP) == '::':
                        listIP.append(remoteIP) 
            return listIP
        #if the img file isn't windows or is an unrecognized format there will be an exception and function will return none
        except:
            return None        

# This function takes the list of remote ips collected from get_conn method and does a dns lookup for each value. Resolved hostnames are added to the iplist and returned
def SearchIP(listIP):
    hostIPList = []
    print "[+] Performing DNS lookup to acquire any related hostnames"
    for ip in listIP:
        #DNS lookup sucess will be added to hostlist
        try:
            t = socket.gethostbyaddr(ip)
            print "DNS lookup resolved %s" % t[0]
            hostIPList.append(t[0])
        except:
            print str(ip) + " Not found"
    #if any ips were resolved add consolidate iplist with host list and return        
    if len(hostIPList) > 0:
        for i in listIP:
            hostIPList.append(i)
        return hostIPList
    #if no ip addresses resolved just return ip list
    else: 
        return listIP

#takes image info object and prints values to std output
def PrintInfo(imageinfo):
    
    p = imageinfo
    for x in p.calculate():
        print "{0}:{1}".format(str(x[0]),str(x[1]))
        
#function takes global list of bad hosts/ips determines if there is a mach to any connected ips/hosts on the img file and if so appends the img name and host name to the 
#matches list that stores all the results
def BadHosts(BADHOSTS, hostList, files, matches):
    
    try:
        fp = open(BADHOSTS, 'r')
        lines = fp.readlines()
        for line in lines:
            if line.strip() in hostList:
                print "bad host found: " + line.strip() + " on " + str(files)
                gl_matches.append((line.strip(), str(files)))
        fp.close()
    except:
        print "[+] error processing bad hosts search"
    
    return gl_matches
                

#Program Entry
if __name__ == '__main__':
    
    #Iniate script and timer
    print "[+] starting script.."
    startTime = time.time()  
    
    
    registry.PluginImporter()
    
    #search global SEARCHDIR for image files
    listOfFiles = os.listdir(SEARCHDIR)
    
    #create instance of config object
    #config = conf.ConfObject()
    try:
        gl_matches= []
        #for each file in list of files initate config object creation and plugin scans, out put results to matches variable
        for files in listOfFiles:
            #time each image file scan
            scanTime = time.time()  
            theFile = "file:///%s/%s" % (SEARCHDIR, files)
            theFile = theFile.replace('\\','/')
            print "[+] trying to load memory file " + theFile
            
            config = GetConfig(theFile)
            if not config == None:
                print "[+] trying to access network connections " 
                hostList = SearchIP(ConnScan(config))
                
                print "[+] Looking for matches is BADHOSTS file "
                if not hostList == None and len(hostList) > 0:
                    gl_matches= BadHosts(BADHOSTS, hostList, files, gl_matches)
                    
                else:
                    print "[+] No connections found or Host List is empty"
                    
                endScanTime = time.time() - scanTime
                print'[+] Elapsed Scan Time for file: ', endScanTime, 'Seconds'
            else:
                print'[+] Memory file is not from Windows source or error processing : ' + files
    except:
        print "error opening file"
   
    #if we found any matches in BADHOSTS file with connections in the images we scanned we will print them     
    if len(gl_matches) > 0:
        print'[+] ============================================================='
        print'[+] SCAN RESULTS: '
        print'[+] ============================================================='
        for i in gl_matches:
            print "{0}:\t{1}".format(str(i[0]),str(i[1]))
    else:
        print "[+] No bad host connections found or Host List is empty"
   
    
    

    print "[+] Script Completed"   
    elapsedTime = time.time() - startTime
    print'[+] Elapsed Time: ', elapsedTime, 'Seconds'