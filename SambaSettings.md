[Movies]
  path = /mnt/movies
  writable = yes
  guest ok = yes
  read only = no
  create mode = 0777
  directory mode = 0777
  force user = nobody
  force directory mode = 2770

[Software]
  path = /mnt/software
  writable = yes
  guest ok = yes
  read only = no
  create mode = 0777
  directory mode = 0777
  force user = nobody 
  force directory mode = 2770


Those are the samba shares that I use. Add these to the bottom of /etc/samba/smb.conf. Also, make the mountpoints owned by nobody:nogroup by doing: sudo chown -R nobody:nogroup /mnt/movies. Repeat for other mountpoints. Also do: sudo chmod 777 /mnt/movies. Repeat for other shares. This is normally a terrible idea on Linux - don't do this unless you implicity trust the network. But for Samba 777 means somewhat different as it maps those bits to DOS file bits so it's kind of necessary. Or at least the internet tells me so.
