.PHONY:all ipc process syscall files tcp container oomkill tcpconnlat bindsnoop biolatency biopattern biosnoop biostacks bitesize funclatency llcstat mountsnoop opensnoop sigsnoop syscount tcprtt memleak capable syscount hot-update

all: ipc process syscall files tcp container oomkill tcpconnlat bindsnoop biosnoop bitesize funclatency llcstat mountsnoop opensnoop sigsnoop syscount tcprtt memleak capable hot-update

bindsnoop:
	@make -C bindsnoop

biolatency:
	@make -C biolatency

biopattern:
	@make -C biopattern

biostacks:
	@make -C biostacks

hot-update:
	@make -C hot-update

# bitesize:
# 	@make -C bitesize

container:
	@make -C container

files:
	@make -C files

funclatency:
	@make -C funclatency

ipc:
	@make -C ipc

llcstat:
	@make -C llcstat

memleak:
	@make -C memleak

mountsnoop:
	@make -C mountsnoop

oomkill:
	@make -C oomkill

opensnoop:
	@make -C opensnoop

process:
	@make -C process

# profile:
# 	@make -C profile

# seccomp:
# 	@make -C seccomp

sigsnoop:
	@make -C sigsnoop

syscall:
	@make -C syscall

syscount:
	@make -C syscount

tcp:
	@make -C tcpconnect

tcpconnlat:
	@make -C tcpconnlat

tcprtt:
	@make -C tcprtt

capable:
	@make -C capable

clean:
	@make -C bindsnoop clean
	@make -C biolatency clean
	@make -C biopattern clean
	@make -C biosnoop clean
	@make -C biostacks clean
	@make -C bitesize clean
	@make -C container clean
	@make -C files clean
	@make -C funclatency clean
	@make -C ipc clean
	@make -C llcstat clean
	@make -C memleak clean
	@make -C mountsnoop clean
	@make -C oomkill clean
	@make -C opensnoop clean
	@make -C process clean
	# @make -C profile clean
	# @make -C seccomp clean
	@make -C sigsnoop clean
	@make -C bindsnoop clean
	@make -C syscall clean
	@make -C syscount clean
	@make -C tcpconnect clean
	@make -C tcpconnlat clean
	@make -C tcprtt clean
	@make -C hot-update clean
