# LazyEnum

#########################################################################
#                                                                       #
#   _                    _____                               _   ___    #
#  | |    __ _ _____   _| ____|_ __  _   _ _ __ ___   __   _/ | / _ \   #
#  | |   / _` |_  / | | |  _| | '_ \| | | | '_ ` _ \  \ \ / / || | | |  #
#  | |__| (_| |/ /| |_| | |___| | | | |_| | | | | | |  \ V /| || |_| |  #
#  |_____\__,_/___|\__, |_____|_| |_|\__,_|_| |_| |_|   \_/ |_(_)___/   #
#                  |___/                                                #
#                                                                       #
#########################################################################

            LazyEnum built by lazy people for Lazy people


Usage: python LazyEnum.py [light/medium/heavy] -H 127.0.0.1 -w /usr/share/wordlists/rockyou.txt
FLAGS:

    -debug  For debugging purposes, prints out more logs
    -D      domain
    -H      Host/IPAddress (required)
    -w      wordlist path (required)

Eg.
python LazyEnum.py medium -H 127.0.0.1 -w /usr/share/wordlists/rockyou.txt -debug
python LazyEnum.py medium -H 127.0.0.1 -D test.local -w /usr/share/wordlists/rockyou.txt -debug
