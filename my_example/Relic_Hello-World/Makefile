#RIOTBASE ?= /home/maksim/code/RIOT

export RELIC_CONFIG_FLAGS=-DARCH=x86 -DQUIET=off -DWORD=32 -DFP_PRIME=255 -DWITH=ALL -DSEED=ZERO -DBENCH=0 -DTESTS=0 #-DRAND=HASH 
#export RELIC_CONFIG_FLAGS=-DARCH=x86 -DQUIET=off -DWSIZE=32 -DFP_PRIME=255 -DWITH=ALL -DSEED=ZERO -DBENCH=1 -DTESTS=0 -DRAND=HASHD #relic master needs hashd

# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

USEPKG += relic

include $(RIOTBASE)/Makefile.include
