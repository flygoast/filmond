filmond
===================

`filmond` is a file monitor and a file information collector implemented using
linux inotify.

When some files created, changed, accessed or deleted, it will send 
informations of the file to a controling server which you should 
prepare for gathering the reporting.

The information is reported through HTTP. You can use any server-end script
to process them.
