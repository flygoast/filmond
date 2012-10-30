filmond
===================

filmond is a file monitor and file information collector implemented using
linux inotify.

When some files created, changed, accessed or deleted, it will send 
informations of the file to a controling server which you should 
prepare for gathering the reporting.

The information reported with HTTP. You can use any server client script
to process them.
