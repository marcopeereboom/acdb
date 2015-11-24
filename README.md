# Amazon Cloud Drive Backup - acdb

This repo contains the building blocks and a simple tar like tool to create deduplicated backups on Amazon Cloud Drive.

The repo has the following pieces:
  - acd - Amazon Cloud Drive REST API implementation
  - acdbackup - Tar like backup tool
  - debug - Debug library for all pieces
  - metadata - External metadata specification
  - sfe - Standalone file encrypting testing tool
  - shared - Code that needs to be shared between packages

In order to get this working one must sign up for an Amazon Cloud Drive account.  Furthermore one must create Amazon Cloud Drive credentials.  See the credentials section for more information.

### Installing the pieces

Install acdbackup utility and all dependencies:
```
go get github.com/marcopeereboom/acdb/acdbackup
```

Next up we need to download the Amazon Cloud Drive oAuth credentials (do read the caveat at the bottom of this readme).
Go to https://go-acd.appspot.com and click on "Download my credentials as acd-token.json".
Note that this site will redirect you to amazon.com and will ask you to login; this is expected.

Create the .acdbackup directory in your home directory and copy acd-token.json to it.  E.g.
```
$ mkdir ~/.acdbackup
$ cp ~/Downloads/acd-token.json ~/.acdbackup/
```

Now launch acdbackup with the -T option (list remote metadata) which at this point will detect that it is the first time being run and will generate new keys and ask for a password to encrypt those keys.  The keys are encrypted and uploaded to the cloud for safe keeping.  Do not lose your password!  It can NOT be recovered

For example:
```
$ acdbackup -T
Cloud Drive does not have a copy of the secrets.  Please enter the password to encrypt the secrets.  Loss of this password is unrecoverable!
Password:
Again   :
$ acdbackup -T
          168  Tue 24 Nov 2015 14:31:18  secrets
$
```

Running acdbackup with out any switches will print out the online help.  Anyone familiar with tar should be able to run this tool pretty easily.  The big difference being that data and metadata end up on the cloud.

### Creating a backup

Creating a backup a backup of the test directory requires the -c switch.  -z enables compression and -v enables verbosity.
For example:
```
$ acdbackup -c -z -v test
drwxr-xr-x             306 test
drwxr-xr-x             136 test/a
drwxr-xr-x              68 test/a/aaa
-rw-r--r--               0 test/a/qa
-rw-r--r--               8 test/aa new => e9972dac6facf6e77c17b2deeeef4f42a64bd031247dda75aa811402306746c8
drwxr-xr-x             170 test/b
-rw-r--r--               0 test/b/bee
-rw-r--r--               0 test/b/beee
-rw-r--r--               0 test/b/beeee
-rw-r--r--               8 test/bb deduped => e9972dac6facf6e77c17b2deeeef4f42a64bd031247dda75aa811402306746c8
drwxr-xr-x             136 test/c
-rw-r--r--               0 test/c/cfile
drwxr-xr-x              68 test/c/inc
-rw-r--r--               7 test/cc new => 4afd27cca4740944f39998f3e6949cf7075bfac718b7888978628c0ef6ef9e35
drwxr-xr-x             136 test/ccc
-rw-r--r--               0 test/ccc/cfile
drwxr-xr-x              68 test/ccc/inc
backup complete: 20151017.100837
```

### Extracting a backup

Extracting the freshly made backup to the directory moo is as follows:
```
acdbackup -x -p -C moo -f 20151017.100837
drwxr-xr-x               0 test
drwxr-xr-x               0 test/a
drwxr-xr-x               0 test/a/aaa
-rw-r--r--               0 test/a/qa
-rw-r--r--               8 test/aa
drwxr-xr-x               0 test/b
-rw-r--r--               0 test/b/bee
-rw-r--r--               0 test/b/beee
-rw-r--r--               0 test/b/beeee
-rw-r--r--               8 test/bb
drwxr-xr-x               0 test/c
-rw-r--r--               0 test/c/cfile
drwxr-xr-x               0 test/c/inc
-rw-r--r--               7 test/cc
drwxr-xr-x               0 test/ccc
-rw-r--r--               0 test/ccc/cfile
drwxr-xr-x               0 test/ccc/inc
```

-C is the target directory and -p restores original permissions and ownership.

### To Do

There are a whole lot of features missing such as single file extract and metadata listings etc.  I did however decide to release this so that people can play and have an idea where this is going.

Currently the code is suboptimal because it uses as much memory as a file is big and the nonce is random instead of a counter. These things will be corrected as I go.

Do not use this for sensitive data yet.  The crypto code path has not been audited yet.

### Amazon Cloud Drive credentials

Amazon Cloud Drive uses
[oAuth 2.0 for authentication](https://developer.amazon.com/public/apis/experience/cloud-drive/content/restful-api-getting-started).
The [token server](https://github.com/go-acd/token-server) takes care of
the oAuth authentication. For your convenience, an instance of the
server is deployed at:

https://go-acd.appspot.com

NOTE: this code and service is not maintained by the author of this repo.  Use at your own risk.  Better yet, deploy your own!

# License ![License](https://img.shields.io/badge/license-ISC-blue.svg)
All code is ISC licensed except acdb/acd/token; that is MIT licensed and
copyright (c) 2015 Wael Nasreddine <wael.nasreddine@gmail.com>.
