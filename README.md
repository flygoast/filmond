filmond
========

Description
-----------

`filmond` is a file monitor and a file information collector implemented using
Linux inotify. So it only can run on Linux.

When some files created, changed, accessed or deleted, it will send 
informations of the file to a controling server which you should 
prepare for gathering the reporting.

The information is reported through HTTP. You can use any server-end script
to process them. You can also write your plugin to process the file event
according to your need. Please refer the plugin directory.

Plugins
-------

* **submit**: By HTTP, submit file information to remote server.

* **chmod**: Process invalid file and directory permisssion.

* **demo**: A demo as tutorial for filmond plugin development.


Requirements
------------

* inotifytool(https://github.com/rvoicilas/inotify-tools)

* libcurl(https://github.com/bagder/curl)

* json-c(https://github.com/json-c/json-c)

* tokyocabinet(http://fallabs.com/tokyocabinet)


Build
-----

    # make
    # make install


Limits
------

It can ONLY run at Linux.

